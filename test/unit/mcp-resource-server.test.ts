import { describe, expect, it, vi } from "vitest"
import {
  authorizeMcpRequest,
  buildMcpProtectedResourceMetadata,
  type McpIntrospectionOptions,
  mcpProtectedResourceMetadataResponse,
  mcpResourceMetadataUrl,
} from "../../src/mcp/resource-server"

const RESOURCE = "https://mcp.example.com/v1/mcp"
const ISSUER = "https://auth.example.com"
const METADATA_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/v1/mcp"

const OPTIONS = {
  resource: RESOURCE,
  authorizationServers: [ISSUER],
  scopesSupported: ["mcp.tools.read", "mcp.tools.execute"],
  issuer: ISSUER,
  introspectionEndpoint: `${ISSUER}/oauth/introspect`,
  clientId: "mcp_resource_server",
  clientSecret: "resource-server-secret",
} as const satisfies McpIntrospectionOptions

function active(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    active: true,
    sub: "usr_123",
    aud: RESOURCE,
    iss: ISSUER,
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000) - 10,
    jti: "at_123",
    scope: "mcp.tools.read mcp.tools.execute",
    client_id: "https://client.example.com/oauth/client.json",
    token_use: "access_token",
    token_type: "Bearer",
    ...overrides,
  }
}

describe("MCP protected-resource metadata", () => {
  it("uses the RFC 9728 path-aware well-known location", async () => {
    expect(mcpResourceMetadataUrl(RESOURCE)).toBe(METADATA_URL)
    expect(buildMcpProtectedResourceMetadata(OPTIONS)).toEqual({
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      scopes_supported: ["mcp.tools.read", "mcp.tools.execute"],
      bearer_methods_supported: ["header"],
    })

    const response = mcpProtectedResourceMetadataResponse(OPTIONS)
    expect(response.status).toBe(200)
    expect(response.headers.get("access-control-allow-origin")).toBe("*")
    expect(await response.json()).toEqual(buildMcpProtectedResourceMetadata(OPTIONS))
  })

  it("rejects ambiguous or insecure production URLs", () => {
    expect(() => mcpResourceMetadataUrl("http://mcp.example.com/mcp")).toThrow(TypeError)
    expect(() => mcpResourceMetadataUrl("https://mcp.example.com/mcp?tenant=1")).toThrow(TypeError)
    expect(mcpResourceMetadataUrl("http://127.0.0.1:8788/mcp")).toBe(
      "http://127.0.0.1:8788/.well-known/oauth-protected-resource/mcp",
    )
    expect(() =>
      buildMcpProtectedResourceMetadata({
        ...OPTIONS,
        authorizationServers: [] as unknown as [string, ...string[]],
      }),
    ).toThrow("at least one issuer")
  })
})

describe("authorizeMcpRequest", () => {
  it("returns a discovery challenge before calling introspection when the token is missing", async () => {
    const fetcher = vi.fn<typeof fetch>()
    const result = await authorizeMcpRequest(
      new Request(RESOURCE, { method: "POST" }),
      ["mcp.tools.read"],
      { ...OPTIONS, fetcher },
    )

    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.status).toBe(401)
    expect(result.response.headers.get("www-authenticate")).toContain(
      `resource_metadata="${METADATA_URL}"`,
    )
    expect(result.response.headers.get("www-authenticate")).toContain('scope="mcp.tools.read"')
    expect(fetcher).not.toHaveBeenCalled()
  })

  it("returns verified identity and scope context for an active audience-bound token", async () => {
    const fetcher: typeof fetch = async (input, init) => {
      expect(String(input)).toBe(`${ISSUER}/oauth/introspect`)
      expect(init?.method).toBe("POST")
      expect(new Headers(init?.headers).get("authorization")).toBe(
        `Basic ${btoa("mcp_resource_server:resource-server-secret")}`,
      )
      expect(new URLSearchParams(String(init?.body)).get("token")).toBe("access-token")
      expect(init?.redirect).toBe("manual")
      expect(init?.signal).toBeInstanceOf(AbortSignal)
      return Response.json(active())
    }
    const result = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: "Bearer access-token" } }),
      ["mcp.tools.execute"],
      { ...OPTIONS, fetcher },
    )

    expect(result).toMatchObject({
      ok: true,
      context: {
        subject: "usr_123",
        audience: RESOURCE,
        scopes: ["mcp.tools.read", "mcp.tools.execute"],
        clientId: "https://client.example.com/oauth/client.json",
      },
    })
  })

  it("rejects wrong-audience, expired, and malformed active responses as invalid tokens", async () => {
    for (const payload of [
      active({ aud: "https://other.example.com/mcp" }),
      active({ exp: Math.floor(Date.now() / 1000) - 1 }),
      active({ scope: "mcp.tools.read mcp.tools.read" }),
    ]) {
      const result = await authorizeMcpRequest(
        new Request(RESOURCE, { headers: { authorization: "Bearer access-token" } }),
        ["mcp.tools.read"],
        { ...OPTIONS, fetcher: async () => Response.json(payload) },
      )
      expect(result.ok).toBe(false)
      if (result.ok) continue
      expect(result.response.status).toBe(401)
      expect(result.response.headers.get("www-authenticate")).toContain('error="invalid_token"')
    }
  })

  it("distinguishes insufficient scope from invalid tokens", async () => {
    const result = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: "Bearer access-token" } }),
      ["mcp.tools.execute"],
      { ...OPTIONS, fetcher: async () => Response.json(active({ scope: "mcp.tools.read" })) },
    )

    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.status).toBe(403)
    expect(result.response.headers.get("www-authenticate")).toContain('error="insufficient_scope"')
  })

  it("fails closed when the authorization service is unavailable or returns oversized data", async () => {
    const unavailable = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: "Bearer access-token" } }),
      ["mcp.tools.read"],
      { ...OPTIONS, fetcher: async () => new Response(null, { status: 502 }) },
    )
    expect(unavailable.ok).toBe(false)
    if (!unavailable.ok) expect(unavailable.response.status).toBe(503)

    const oversized = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: "Bearer access-token" } }),
      ["mcp.tools.read"],
      {
        ...OPTIONS,
        fetcher: async () =>
          new Response("{}", {
            headers: { "content-length": String(16 * 1024 + 1) },
          }),
      },
    )
    expect(oversized.ok).toBe(false)
    if (!oversized.ok) expect(oversized.response.status).toBe(503)
  })
})
