import {
  authorizeMcpRequest,
  mcpBearerChallenge,
  mcpProtectedResourceMetadataResponse,
  mcpResourceMetadataUrl,
  type McpIntrospectionOptions,
} from "../../../src/mcp/resource-server"

type ExampleEnv = {
  readonly KEYFORGE_ISSUER: string
  readonly MCP_RESOURCE: string
  readonly MCP_INTROSPECTION_CLIENT_ID: string
  readonly MCP_INTROSPECTION_CLIENT_SECRET: string
}

const READ_SCOPE = "mcp.tools.read"
const EXECUTE_SCOPE = "mcp.tools.execute"
const SCOPES = [READ_SCOPE, EXECUTE_SCOPE, "offline_access"] as const
const MAX_JSON_RPC_BYTES = 64 * 1024
const MCP_PROTOCOL_VERSION = "2025-11-25"

function authorizationOptions(env: ExampleEnv): McpIntrospectionOptions {
  return {
    issuer: env.KEYFORGE_ISSUER,
    resource: env.MCP_RESOURCE,
    authorizationServers: [env.KEYFORGE_ISSUER],
    scopesSupported: SCOPES,
    introspectionEndpoint: `${env.KEYFORGE_ISSUER}/oauth/introspect`,
    clientId: env.MCP_INTROSPECTION_CLIENT_ID,
    clientSecret: env.MCP_INTROSPECTION_CLIENT_SECRET,
  }
}

function rpc(id: unknown, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result }, { headers: { "cache-control": "no-store" } })
}

function rpcError(id: unknown, code: number, message: string, status = 400): Response {
  return Response.json(
    { jsonrpc: "2.0", id, error: { code, message } },
    { status, headers: { "cache-control": "no-store" } },
  )
}

async function readRpcRequest(request: Request): Promise<Record<string, unknown> | null> {
  const declaredLength = request.headers.get("content-length")
  if (declaredLength !== null && Number(declaredLength) > MAX_JSON_RPC_BYTES) return null
  const bytes = await request.arrayBuffer()
  if (bytes.byteLength > MAX_JSON_RPC_BYTES) return null
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null
  } catch {
    return null
  }
}

async function handleMcp(request: Request, env: ExampleEnv): Promise<Response> {
  const origin = request.headers.get("origin")
  if (origin !== null && origin !== new URL(env.MCP_RESOURCE).origin) {
    return Response.json({ error: "invalid_origin" }, { status: 403 })
  }
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim()
  if (contentType !== "application/json") {
    return Response.json({ error: "unsupported_media_type" }, { status: 415 })
  }
  const requestedProtocolVersion = request.headers.get("mcp-protocol-version")
  if (requestedProtocolVersion !== null && requestedProtocolVersion !== MCP_PROTOCOL_VERSION) {
    return Response.json({ error: "unsupported_protocol_version" }, { status: 400 })
  }
  const options = authorizationOptions(env)
  const authorization = await authorizeMcpRequest(request, [READ_SCOPE], options)
  if (!authorization.ok) return authorization.response

  const message = await readRpcRequest(request)
  if (message === null || message["jsonrpc"] !== "2.0" || typeof message["method"] !== "string") {
    return rpcError(message?.["id"] ?? null, -32600, "Invalid Request")
  }
  const id = message["id"] ?? null
  switch (message["method"]) {
    case "initialize":
      return rpc(id, {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "keyforge-mcp-example", version: "0.1.0" },
      })
    case "notifications/initialized":
      return new Response(null, { status: 202 })
    case "tools/list":
      return rpc(id, {
        tools: [
          {
            name: "whoami",
            description: "Return the KeyForge subject and OAuth client for this MCP request.",
            inputSchema: { type: "object", properties: {}, additionalProperties: false },
          },
        ],
      })
    case "tools/call": {
      if (!authorization.context.scopes.includes(EXECUTE_SCOPE)) {
        return Response.json(
          { error: "insufficient_scope" },
          {
            status: 403,
            headers: {
              "cache-control": "no-store",
              "www-authenticate": mcpBearerChallenge(options, {
                error: "insufficient_scope",
                scopes: [READ_SCOPE, EXECUTE_SCOPE],
              }),
            },
          },
        )
      }
      const params = message["params"]
      const toolName =
        typeof params === "object" && params !== null && "name" in params ? params.name : undefined
      if (toolName !== "whoami") return rpcError(id, -32602, "Unknown tool")
      return rpc(id, {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              subject: authorization.context.subject,
              client_id: authorization.context.clientId,
              scopes: authorization.context.scopes,
            }),
          },
        ],
      })
    }
    default:
      return rpcError(id, -32601, "Method not found")
  }
}

export default {
  async fetch(request: Request, env: ExampleEnv): Promise<Response> {
    const url = new URL(request.url)
    const options = authorizationOptions(env)
    if (request.method === "GET" && url.href === mcpResourceMetadataUrl(env.MCP_RESOURCE)) {
      return mcpProtectedResourceMetadataResponse(options)
    }
    if (request.method === "POST" && url.href === env.MCP_RESOURCE) {
      return handleMcp(request, env)
    }
    return Response.json({ error: "not_found" }, { status: 404 })
  },
} satisfies ExportedHandler<ExampleEnv>
