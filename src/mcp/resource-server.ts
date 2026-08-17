import * as z from "zod"

const ACCESS_TOKEN_MAX_LENGTH = 16 * 1024
const INTROSPECTION_RESPONSE_MAX_BYTES = 16 * 1024
const INTROSPECTION_TIMEOUT_MS = 5_000
const OAUTH_SCOPE_MAX_COUNT = 64
const OAUTH_SCOPE_MAX_BYTES = 128
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/
const encoder = new TextEncoder()

function parseScopeString(raw: string): string[] {
  return raw.trim().split(/\s+/).filter(Boolean)
}

function validScopeCatalog(scopes: readonly string[]): boolean {
  return (
    scopes.length <= OAUTH_SCOPE_MAX_COUNT &&
    new Set(scopes).size === scopes.length &&
    scopes.every(
      (scope) =>
        SCOPE_TOKEN.test(scope) &&
        encoder.encode(scope).byteLength > 0 &&
        encoder.encode(scope).byteLength <= OAUTH_SCOPE_MAX_BYTES,
    )
  )
}

export type McpProtectedResourceOptions = {
  readonly resource: string
  readonly authorizationServers: readonly [string, ...string[]]
  readonly scopesSupported: readonly string[]
  /** Override only when metadata is intentionally hosted at a different URL. */
  readonly resourceMetadataUrl?: string
}

export type McpProtectedResourceMetadata = {
  readonly resource: string
  readonly authorization_servers: readonly string[]
  readonly scopes_supported: readonly string[]
  readonly bearer_methods_supported: readonly ["header"]
}

export type McpIntrospectionOptions = McpProtectedResourceOptions & {
  readonly issuer: string
  readonly introspectionEndpoint: string
  readonly clientId: string
  readonly clientSecret: string
  readonly fetcher?: typeof fetch
}

export type McpAuthorizationContext = {
  readonly subject: string
  readonly clientId: string
  readonly audience: string
  readonly scopes: readonly string[]
  readonly expiresAt: number
  readonly issuedAt: number | null
  readonly tokenId: string | null
}

export type McpAuthorizationResult =
  | { readonly ok: true; readonly context: McpAuthorizationContext }
  | { readonly ok: false; readonly response: Response }

const introspectionSchema = z.object({
  active: z.literal(true),
  sub: z.string().min(1),
  aud: z.string().min(1),
  iss: z.string().min(1),
  exp: z.number().int(),
  iat: z.number().int().optional(),
  jti: z.string().optional(),
  scope: z.string(),
  client_id: z.string().min(1),
  token_use: z.literal("access_token"),
  token_type: z.literal("Bearer"),
})

function requireSecureUrl(raw: string, label: string): URL {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new TypeError(`${label} must be an absolute URL`)
  }
  const loopbackHttp =
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
  if (
    (url.protocol !== "https:" && !loopbackHttp) ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.search !== ""
  ) {
    throw new TypeError(`${label} must be HTTPS (loopback HTTP is allowed for local development)`)
  }
  return url
}

function validateOptions(options: McpProtectedResourceOptions): void {
  requireSecureUrl(options.resource, "resource")
  if (options.authorizationServers.length === 0) {
    throw new TypeError("authorizationServers must contain at least one issuer")
  }
  for (const issuer of options.authorizationServers)
    requireSecureUrl(issuer, "authorization server")
  if (!validScopeCatalog(options.scopesSupported)) {
    throw new TypeError("scopesSupported contains duplicated, malformed, or oversized scopes")
  }
  if (options.resourceMetadataUrl !== undefined) {
    requireSecureUrl(options.resourceMetadataUrl, "resource metadata URL")
  }
}

/** RFC 9728 well-known location for a canonical resource URI. */
export function mcpResourceMetadataUrl(resource: string): string {
  const url = requireSecureUrl(resource, "resource")
  const suffix = url.pathname === "/" ? "" : url.pathname
  return `${url.origin}/.well-known/oauth-protected-resource${suffix}`
}

export function buildMcpProtectedResourceMetadata(
  options: McpProtectedResourceOptions,
): McpProtectedResourceMetadata {
  validateOptions(options)
  return {
    resource: options.resource,
    authorization_servers: [...options.authorizationServers],
    scopes_supported: [...options.scopesSupported],
    bearer_methods_supported: ["header"],
  }
}

export function mcpProtectedResourceMetadataResponse(
  options: McpProtectedResourceOptions,
): Response {
  return Response.json(buildMcpProtectedResourceMetadata(options), {
    headers: {
      "access-control-allow-origin": "*",
      "cache-control": "public, max-age=300",
    },
  })
}

function quoteChallengeValue(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`
}

type ChallengeOptions = {
  readonly error?: "invalid_token" | "insufficient_scope"
  readonly scopes?: readonly string[]
  readonly description?: string
}

export function mcpBearerChallenge(
  options: McpProtectedResourceOptions,
  challenge: ChallengeOptions = {},
): string {
  validateOptions(options)
  if (challenge.scopes !== undefined && !validScopeCatalog(challenge.scopes)) {
    throw new TypeError("challenge scopes are invalid")
  }
  const metadataUrl = options.resourceMetadataUrl ?? mcpResourceMetadataUrl(options.resource)
  const parameters = [`resource_metadata=${quoteChallengeValue(metadataUrl)}`]
  if (challenge.error !== undefined)
    parameters.push(`error=${quoteChallengeValue(challenge.error)}`)
  if (challenge.scopes !== undefined && challenge.scopes.length > 0) {
    parameters.push(`scope=${quoteChallengeValue(challenge.scopes.join(" "))}`)
  }
  if (challenge.description !== undefined) {
    parameters.push(`error_description=${quoteChallengeValue(challenge.description)}`)
  }
  return `Bearer ${parameters.join(", ")}`
}

function authorizationFailure(
  options: McpProtectedResourceOptions,
  status: 401 | 403,
  challenge: ChallengeOptions,
): McpAuthorizationResult {
  return {
    ok: false,
    response: Response.json(
      { error: challenge.error ?? "authorization_required" },
      {
        status,
        headers: {
          "cache-control": "no-store",
          "www-authenticate": mcpBearerChallenge(options, challenge),
        },
      },
    ),
  }
}

async function readIntrospectionJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get("content-length")
  if (declaredLength !== null && Number(declaredLength) > INTROSPECTION_RESPONSE_MAX_BYTES) {
    await response.body?.cancel()
    throw new Error("introspection response is too large")
  }
  if (response.body === null) throw new Error("introspection response is empty")
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > INTROSPECTION_RESPONSE_MAX_BYTES) {
        await reader.cancel()
        throw new Error("introspection response is too large")
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return JSON.parse(new TextDecoder().decode(bytes))
}

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization")
  if (authorization === null || !/^Bearer /i.test(authorization)) return null
  const token = authorization.slice(7).trim()
  if (token === "" || token.length > ACCESS_TOKEN_MAX_LENGTH) return null
  return token
}

/**
 * Validate one MCP request through KeyForge's RFC 7662 endpoint. Successful
 * results carry identity/scope context; application-specific tool and object
 * authorization remains the MCP server's responsibility.
 */
export async function authorizeMcpRequest(
  request: Request,
  requiredScopes: readonly string[],
  options: McpIntrospectionOptions,
): Promise<McpAuthorizationResult> {
  validateOptions(options)
  requireSecureUrl(options.issuer, "issuer")
  requireSecureUrl(options.introspectionEndpoint, "introspection endpoint")
  if (!validScopeCatalog(requiredScopes)) {
    throw new TypeError("requiredScopes contains invalid OAuth scope tokens")
  }
  const token = bearerToken(request)
  if (token === null) return authorizationFailure(options, 401, { scopes: requiredScopes })

  let response: Response
  try {
    response = await (options.fetcher ?? fetch)(options.introspectionEndpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Basic ${btoa(`${options.clientId}:${options.clientSecret}`)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token, token_type_hint: "access_token" }).toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(INTROSPECTION_TIMEOUT_MS),
    })
  } catch {
    return {
      ok: false,
      response: Response.json(
        { error: "authorization_service_unavailable" },
        { status: 503, headers: { "cache-control": "no-store", "retry-after": "5" } },
      ),
    }
  }
  if (!response.ok) {
    await response.body?.cancel()
    return {
      ok: false,
      response: Response.json(
        { error: "authorization_service_unavailable" },
        { status: 503, headers: { "cache-control": "no-store", "retry-after": "5" } },
      ),
    }
  }

  let raw: unknown
  try {
    raw = await readIntrospectionJson(response)
  } catch {
    return {
      ok: false,
      response: Response.json(
        { error: "authorization_service_unavailable" },
        { status: 503, headers: { "cache-control": "no-store", "retry-after": "5" } },
      ),
    }
  }
  if (typeof raw !== "object" || raw === null || !("active" in raw) || raw.active !== true) {
    return authorizationFailure(options, 401, {
      error: "invalid_token",
      scopes: requiredScopes,
    })
  }
  const parsed = introspectionSchema.safeParse(raw)
  if (
    !parsed.success ||
    parsed.data.iss !== options.issuer ||
    parsed.data.aud !== options.resource ||
    parsed.data.exp <= Math.floor(Date.now() / 1000)
  ) {
    return authorizationFailure(options, 401, {
      error: "invalid_token",
      scopes: requiredScopes,
    })
  }
  const scopes = parseScopeString(parsed.data.scope)
  if (!validScopeCatalog(scopes)) {
    return authorizationFailure(options, 401, {
      error: "invalid_token",
      scopes: requiredScopes,
    })
  }
  if (requiredScopes.some((scope) => !scopes.includes(scope))) {
    return authorizationFailure(options, 403, {
      error: "insufficient_scope",
      scopes: requiredScopes,
      description: "Additional permission is required for this MCP operation",
    })
  }
  return {
    ok: true,
    context: {
      subject: parsed.data.sub,
      clientId: parsed.data.client_id,
      audience: parsed.data.aud,
      scopes,
      expiresAt: parsed.data.exp,
      issuedAt: parsed.data.iat ?? null,
      tokenId: parsed.data.jti ?? null,
    },
  }
}
