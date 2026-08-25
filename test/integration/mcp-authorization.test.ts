import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { createSession } from "../../src/auth/session"
import {
  approveMetadataClient,
  createClient,
  getClientById,
  revokeMetadataClientApproval,
} from "../../src/db/queries/clients"
import { getConsent, saveConsent } from "../../src/db/queries/consents"
import { createResource } from "../../src/db/queries/resources"
import { createUser } from "../../src/db/queries/users"
import { authorizeMcpRequest } from "../../src/mcp/resource-server"
import { resolveAuthorizationClient } from "../../src/oauth/client-id-metadata"
import { resolveResourceForScopes } from "../../src/oauth/resources"
import { hashClientSecret } from "../../src/security/client-secret"

const ISSUER = "https://auth.pangda.app"
const RESOURCE = "https://mcp.example.com/v1/mcp"
const CLIENT_ID = "https://client.example.com/oauth/client.json"
const REDIRECT_URI = "https://client.example.com/oauth/callback"
const SCOPES = ["mcp.tools.read", "mcp.tools.execute"] as const
const REQUESTED_SCOPE = "mcp.tools.read offline_access"
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
const INTROSPECTOR = "svc_internal_worker"
const INTROSPECTOR_SECRET = "mcp-introspection-secret-abc123"

let sessionToken = ""
let userId = ""

function clientMetadata(): Record<string, unknown> {
  return {
    client_id: CLIENT_ID,
    client_name: "Example MCP Client",
    redirect_uris: [REDIRECT_URI],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  }
}

beforeEach(async () => {
  await Promise.all([
    env.RATE_LIMIT.getByName("oauth:introspect:ip:unknown").reset(),
    env.RATE_LIMIT.getByName("oauth:authorize-metadata:ip:unknown").reset(),
  ])
  await env.DB.batch([
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
    env.DB.prepare("DELETE FROM groups WHERE id = 'grp_test_mcp_scope_deny'"),
    env.DB.prepare("DELETE FROM oauth_clients WHERE registration_type = 'client_id_metadata'"),
    env.DB.prepare("DELETE FROM oauth_clients WHERE client_id = 'test_mcp_static'"),
    env.DB.prepare("DELETE FROM oauth_resources WHERE resource_uri = ?").bind(RESOURCE),
  ])
  await createResource(env, {
    resourceUri: RESOURCE,
    name: "Example MCP Server",
    allowedScopes: SCOPES,
    mcpEnabled: true,
    metadataClientPolicy: "consent_required",
  })
  await env.DB.prepare(
    `INSERT INTO oauth_resource_permission_groups (resource_uri, group_id, created_at)
     VALUES (?, 'grp_seed_employees', unixepoch())`,
  )
    .bind(RESOURCE)
    .run()
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO permission_group_rules
         (id, group_id, effect, condition_json, position, created_at, updated_at)
       VALUES (
         'prule_test_mcp_api', 'grp_seed_employees', 'allow',
         '{"field":"api","operator":"equals","value":"https://mcp.example.com/v1/mcp"}',
         (SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = 'grp_seed_employees'),
         unixepoch(), unixepoch()
       )`,
    ),
    env.DB.prepare(
      `INSERT INTO permission_group_rules
         (id, group_id, effect, condition_json, position, created_at, updated_at)
       VALUES (
         'prule_test_mcp_read', 'grp_seed_employees', 'allow',
         '{"operator":"and","conditions":[{"field":"api","operator":"equals","value":"https://mcp.example.com/v1/mcp"},{"field":"scope","operator":"equals","value":"mcp.tools.read"}]}',
         (SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = 'grp_seed_employees'),
         unixepoch(), unixepoch()
       )`,
    ),
    env.DB.prepare(
      `INSERT INTO permission_group_rules
         (id, group_id, effect, condition_json, position, created_at, updated_at)
       VALUES (
         'prule_test_mcp_execute', 'grp_seed_employees', 'allow',
         '{"operator":"and","conditions":[{"field":"api","operator":"equals","value":"https://mcp.example.com/v1/mcp"},{"field":"scope","operator":"equals","value":"mcp.tools.execute"}]}',
         (SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = 'grp_seed_employees'),
         unixepoch(), unixepoch()
       )`,
    ),
  ])

  const user = await createUser(env, {
    email: "mcp-user@pangda.app",
    alias: "mcp-user",
    name: "MCP User",
    emailVerified: true,
  })
  userId = user.id
  await env.DB.prepare(
    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_employees', unixepoch())",
  )
    .bind(user.id)
    .run()
  sessionToken = (
    await createSession(env, { userId: user.id, authMethod: "password", ttlSeconds: 3600 })
  ).token

  await env.DB.prepare(
    `UPDATE oauth_clients
       SET client_secret_hash = ?, allowed_resources_json = ?
       WHERE client_id = ?`,
  )
    .bind(await hashClientSecret(INTROSPECTOR_SECRET), JSON.stringify([RESOURCE]), INTROSPECTOR)
    .run()
})

async function discoverClient() {
  return resolveAuthorizationClient(env, CLIENT_ID, RESOURCE, {
    resolveHost: async () => ["1.1.1.1"],
    fetcher: async () =>
      new Response(JSON.stringify(clientMetadata()), {
        headers: {
          "cache-control": "public, max-age=600",
          "content-type": "application/json",
        },
      }),
  })
}

function authorizationUrl(overrides: Record<string, string> = {}): string {
  const url = new URL(`${ISSUER}/oauth/authorize`)
  url.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: REQUESTED_SCOPE,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE,
    ...overrides,
  }).toString()
  return url.toString()
}

async function obtainCode(): Promise<string> {
  const response = await SELF.fetch(authorizationUrl(), {
    headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
    redirect: "manual",
  })
  expect(response.status).toBe(302)
  const code = new URL(response.headers.get("location") ?? "").searchParams.get("code")
  expect(code).not.toBeNull()
  return code ?? ""
}

function tokenRequest(values: Record<string, string>): Promise<Response> {
  return SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(values).toString(),
  })
}

function exchangeCode(code: string, resource?: string): Promise<Response> {
  return tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: VERIFIER,
    client_id: CLIENT_ID,
    ...(resource === undefined ? {} : { resource }),
  })
}

describe("MCP authorization integration", () => {
  it("opts resources into CIMD explicitly and persists a policy-gated public client", async () => {
    await env.DB.prepare(
      "UPDATE oauth_resources SET metadata_client_policy = 'disabled' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()
    const fetcher = vi.fn<typeof fetch>()
    expect(
      await resolveAuthorizationClient(env, CLIENT_ID, RESOURCE, {
        fetcher,
        resolveHost: async () => ["1.1.1.1"],
      }),
    ).toBeNull()
    expect(fetcher).not.toHaveBeenCalled()

    await env.DB.prepare(
      "UPDATE oauth_resources SET metadata_client_policy = 'consent_required' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()
    const client = await discoverClient()
    expect(client).toMatchObject({
      clientId: CLIENT_ID,
      name: "Example MCP Client",
      type: "public",
      clientKind: "application",
      registrationType: "client_id_metadata",
      requirePkce: true,
      allowedResources: [RESOURCE],
      allowedScopes: [...SCOPES, "openid", "profile", "email", "offline_access"],
    })
    expect(
      await env.DB.prepare(
        `SELECT COUNT(*) AS count
           FROM oauth_client_permission_groups AS access
           JOIN groups ON groups.id = access.group_id
           WHERE access.client_id = ? AND groups.name = 'all'`,
      )
        .bind(CLIENT_ID)
        .first<number>("count"),
    ).toBe(0)

    await env.DB.prepare("UPDATE oauth_clients SET enabled = 0 WHERE client_id = ?")
      .bind(CLIENT_ID)
      .run()
    expect((await discoverClient())?.enabled).toBe(false)
    await env.DB.prepare("UPDATE oauth_clients SET enabled = 1 WHERE client_id = ?")
      .bind(CLIENT_ID)
      .run()

    await createClient(
      env,
      {
        clientId: "test_mcp_static",
        name: "Static MCP client",
        type: "public",
        clientKind: "application",
        redirectUris: ["https://static-client.example.com/callback"],
        allowedScopes: ["mcp.tools.read"],
        allowedGrantTypes: ["authorization_code"],
        allowedResources: [RESOURCE],
        defaultResource: RESOURCE,
        requirePkce: true,
      },
      null,
    )
    const staticClient = await getClientById(env, "test_mcp_static")
    expect(staticClient).not.toBeNull()
    if (staticClient !== null) {
      await expect(
        resolveResourceForScopes(env, staticClient, null, ["mcp.tools.read"]),
      ).rejects.toMatchObject({ code: "invalid_target" })
      await expect(
        resolveResourceForScopes(env, staticClient, RESOURCE, ["mcp.tools.read"]),
      ).resolves.toBe(RESOURCE)
    }
  })

  it("requires per-resource approval under admin_approved policy", async () => {
    await env.DB.prepare(
      "UPDATE oauth_resources SET metadata_client_policy = 'admin_approved' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()

    expect(await discoverClient()).toBeNull()
    expect(await getClientById(env, CLIENT_ID)).not.toBeNull()
    await expect(approveMetadataClient(env, CLIENT_ID, RESOURCE, userId)).resolves.toBe(true)
    await expect(discoverClient()).resolves.toMatchObject({ clientId: CLIENT_ID })
    await expect(revokeMetadataClientApproval(env, CLIENT_ID, RESOURCE)).resolves.toBe(true)
    expect(await discoverClient()).toBeNull()
  })

  it("requires explicit confirmation when consent steps up to execute", async () => {
    const client = await discoverClient()
    if (client === null) throw new Error("metadata client was not discovered")
    await saveConsent(env, {
      userId,
      clientId: CLIENT_ID,
      resource: RESOURCE,
      scope: "mcp.tools.read",
      metadataFingerprint: client.metadataFingerprint,
    })
    const url = authorizationUrl({ scope: "mcp.tools.read mcp.tools.execute" })
    const page = await SELF.fetch(url, {
      headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
    })
    const csrfCookie = page.headers.get("set-cookie")?.split(";", 1)[0]
    expect(csrfCookie).toBeTruthy()
    expect(page.status).toBe(200)
    const html = await page.text()
    expect(html).toContain("requesting additional permissions")
    expect(html).toContain('name="confirm_elevated"')
    const csrfToken = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1]
    expect(csrfToken).toBeTruthy()

    const decision = new URLSearchParams(new URL(url).search)
    decision.set("csrf_token", csrfToken ?? "")
    decision.set("decision", "approve")
    const denied = await SELF.fetch(`${ISSUER}/oauth/authorize/decision`, {
      method: "POST",
      headers: {
        cookie: `__Host-keyforge_session=${sessionToken}; ${csrfCookie ?? ""}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: decision,
      redirect: "manual",
    })
    expect(denied.status).toBe(302)
    const deniedLocation = new URL(denied.headers.get("location") ?? REDIRECT_URI)
    expect(deniedLocation.searchParams.get("error")).toBe("access_denied")
    expect(deniedLocation.searchParams.get("iss")).toBe(ISSUER)

    decision.set("confirm_elevated", "yes")
    const approved = await SELF.fetch(`${ISSUER}/oauth/authorize/decision`, {
      method: "POST",
      headers: {
        cookie: `__Host-keyforge_session=${sessionToken}; ${csrfCookie ?? ""}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: decision,
      redirect: "manual",
    })
    expect(
      new URL(approved.headers.get("location") ?? REDIRECT_URI).searchParams.get("code"),
    ).toBeTruthy()
    expect((await getConsent(env, userId, CLIENT_ID, RESOURCE))?.scope).toContain(
      "mcp.tools.execute",
    )
  })

  it("completes CIMD consent, resource-bound token exchange, introspection, and live revocation", async () => {
    expect(await discoverClient()).not.toBeNull()

    const consent = await SELF.fetch(authorizationUrl(), {
      headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
      redirect: "manual",
    })
    expect(consent.status).toBe(200)
    const consentHtml = await consent.text()
    expect(consentHtml).toContain("Example MCP Client")
    expect(consentHtml).toContain("client.example.com")
    expect(consentHtml).toContain(REDIRECT_URI)

    await saveConsent(env, {
      userId,
      clientId: CLIENT_ID,
      resource: RESOURCE,
      scope: REQUESTED_SCOPE,
      metadataFingerprint: (await getClientById(env, CLIENT_ID))?.metadataFingerprint ?? null,
    })

    const missingResource = await exchangeCode(await obtainCode())
    expect(missingResource.status).toBe(400)
    expect(await missingResource.json()).toMatchObject({ error: "invalid_request" })

    const tokenResponse = await exchangeCode(await obtainCode(), RESOURCE)
    expect(tokenResponse.status).toBe(200)
    const tokens = await tokenResponse.json<{ access_token: string; refresh_token: string }>()
    expect(tokens.access_token).toBeTruthy()
    expect(tokens.refresh_token).toBeTruthy()

    const refreshWithoutResource = await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
    })
    expect(refreshWithoutResource.status).toBe(400)
    expect(await refreshWithoutResource.json()).toMatchObject({ error: "invalid_request" })

    const refreshed = await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
      resource: RESOURCE,
    })
    expect(refreshed.status).toBe(200)
    const refreshedToken = (await refreshed.json<{ access_token: string }>()).access_token

    const throughKeyForge: typeof fetch = (input, init) => {
      // SELF is an in-process service binding; the adapter's real outbound
      // timeout signal is covered by the unit test and is not transferable to it.
      const { signal: _signal, ...serviceInit } = init ?? {}
      return SELF.fetch(input, serviceInit)
    }
    const authorized = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: `Bearer ${refreshedToken}` } }),
      ["mcp.tools.read"],
      {
        resource: RESOURCE,
        authorizationServers: [ISSUER],
        scopesSupported: SCOPES,
        issuer: ISSUER,
        introspectionEndpoint: `${ISSUER}/oauth/introspect`,
        clientId: INTROSPECTOR,
        clientSecret: INTROSPECTOR_SECRET,
        fetcher: throughKeyForge,
      },
    )
    if (!authorized.ok) {
      throw new Error(
        `MCP adapter rejected the KeyForge token (${authorized.response.status}): ${await authorized.response.text()}`,
      )
    }
    expect(authorized).toMatchObject({
      ok: true,
      context: { subject: userId, audience: RESOURCE, clientId: CLIENT_ID },
    })

    await env.DB.prepare(
      "UPDATE oauth_resources SET metadata_client_policy = 'disabled' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()
    const metadataOptOut = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: `Bearer ${refreshedToken}` } }),
      ["mcp.tools.read"],
      {
        resource: RESOURCE,
        authorizationServers: [ISSUER],
        scopesSupported: SCOPES,
        issuer: ISSUER,
        introspectionEndpoint: `${ISSUER}/oauth/introspect`,
        clientId: INTROSPECTOR,
        clientSecret: INTROSPECTOR_SECRET,
        fetcher: throughKeyForge,
      },
    )
    expect(metadataOptOut.ok).toBe(false)
    if (!metadataOptOut.ok) expect(metadataOptOut.response.status).toBe(401)
    await env.DB.prepare(
      "UPDATE oauth_resources SET metadata_client_policy = 'consent_required' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()

    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO groups (id, name, description, created_at)
         VALUES ('grp_test_mcp_scope_deny', 'test-mcp-scope-deny', NULL, unixepoch())`,
      ),
      env.DB.prepare(
        `INSERT INTO user_groups (user_id, group_id, created_at)
         VALUES (?, 'grp_test_mcp_scope_deny', unixepoch())`,
      ).bind(userId),
      env.DB.prepare(
        `INSERT INTO permission_group_rules
           (id, group_id, effect, condition_json, position, created_at, updated_at)
         VALUES (
           'prule_test_mcp_deny', 'grp_test_mcp_scope_deny', 'deny',
           '{"operator":"and","conditions":[{"field":"api","operator":"equals","value":"https://mcp.example.com/v1/mcp"},{"field":"scope","operator":"equals","value":"mcp.tools.read"}]}',
           0, unixepoch(), unixepoch()
         )`,
      ),
    ])
    const scopeDenied = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: `Bearer ${refreshedToken}` } }),
      ["mcp.tools.read"],
      {
        resource: RESOURCE,
        authorizationServers: [ISSUER],
        scopesSupported: SCOPES,
        issuer: ISSUER,
        introspectionEndpoint: `${ISSUER}/oauth/introspect`,
        clientId: INTROSPECTOR,
        clientSecret: INTROSPECTOR_SECRET,
        fetcher: throughKeyForge,
      },
    )
    expect(scopeDenied.ok).toBe(false)
    if (!scopeDenied.ok) expect(scopeDenied.response.status).toBe(401)
    await env.DB.prepare(
      "DELETE FROM user_groups WHERE user_id = ? AND group_id = 'grp_test_mcp_scope_deny'",
    )
      .bind(userId)
      .run()

    await env.DB.prepare(
      "DELETE FROM user_groups WHERE user_id = ? AND group_id = 'grp_seed_employees'",
    )
      .bind(userId)
      .run()
    const revoked = await authorizeMcpRequest(
      new Request(RESOURCE, { headers: { authorization: `Bearer ${refreshedToken}` } }),
      ["mcp.tools.read"],
      {
        resource: RESOURCE,
        authorizationServers: [ISSUER],
        scopesSupported: SCOPES,
        issuer: ISSUER,
        introspectionEndpoint: `${ISSUER}/oauth/introspect`,
        clientId: INTROSPECTOR,
        clientSecret: INTROSPECTOR_SECRET,
        fetcher: throughKeyForge,
      },
    )
    expect(revoked.ok).toBe(false)
    if (!revoked.ok) expect(revoked.response.status).toBe(401)
    expect((await getClientById(env, CLIENT_ID))?.registrationType).toBe("client_id_metadata")
  })

  it("advertises RFC 8414 discovery, CIMD support, and resource-owned MCP scopes", async () => {
    const response = await SELF.fetch(`${ISSUER}/.well-known/oauth-authorization-server`)
    expect(response.status).toBe(200)
    const metadata = await response.json<{
      issuer: string
      scopes_supported: string[]
      client_id_metadata_document_supported: boolean
    }>()
    expect(metadata.issuer).toBe(ISSUER)
    expect(metadata.client_id_metadata_document_supported).toBe(true)
    expect(metadata.scopes_supported).toEqual(expect.arrayContaining([...SCOPES]))
  })

  it("rate limits URL client authorization before fetching metadata", async () => {
    const limiter = env.RATE_LIMIT.getByName("oauth:authorize-metadata:ip:unknown")
    for (let attempt = 0; attempt < 120; attempt += 1) {
      expect((await limiter.check(120, 300)).allowed).toBe(true)
    }

    const blocked = await SELF.fetch(authorizationUrl(), { redirect: "manual" })
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0)
    expect(await blocked.text()).toContain("Too many authorization requests")
    expect(await getClientById(env, CLIENT_ID)).toBeNull()
  })
})
