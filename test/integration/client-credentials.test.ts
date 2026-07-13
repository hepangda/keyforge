import { env, SELF } from "cloudflare:test"
import { createLocalJWKSet, jwtVerify } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { hashClientSecret } from "../../src/security/client-secret"
import { getPublicJwks } from "../../src/tokens/key-rotation"

const ISSUER = "https://auth.pangda.app"
const SVC = "svc_internal_worker"
const SECRET = "s3cr3t-high-entropy-value-abc123xyz"
const RESOURCE = "https://api.pangda.app"

function basicAuth(id: string, secret: string): string {
  return `Basic ${btoa(`${id}:${secret}`)}`
}

async function tokenRequest(body: Record<string, string>, authHeader?: string): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
  }
  if (authHeader !== undefined) {
    headers["authorization"] = authHeader
  }
  return SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers,
    body: new URLSearchParams(body).toString(),
  })
}

beforeEach(async () => {
  await env.RATE_LIMIT.getByName("oauth:token:ip:unknown").reset()
  await env.DB.prepare(
    `UPDATE oauth_resources
     SET allowed_scopes_json = '["openid","profile","email","groups","offline_access","api.read","api.write"]'
     WHERE resource_uri = ?`,
  )
    .bind(RESOURCE)
    .run()
  const hash = await hashClientSecret(SECRET)
  await env.DB.prepare("UPDATE oauth_clients SET client_secret_hash = ? WHERE client_id = ?")
    .bind(hash, SVC)
    .run()
  await env.DB.prepare(
    `INSERT OR REPLACE INTO oauth_clients
       (client_id, client_secret_hash, type, client_kind, name, redirect_uris_json,
        allowed_scopes_json, allowed_grant_types_json, allowed_resources_json,
        default_resource, require_pkce, enabled, created_at, updated_at)
     VALUES ('pub_cc_test', NULL, 'public', 'application', 'Public CC', '[]',
             '["api.read"]', '["client_credentials"]', '["https://api.pangda.app"]',
             'https://api.pangda.app', 0, 1, unixepoch(), unixepoch())`,
  ).run()
})

describe("POST /oauth/token — client_credentials", () => {
  it("rejects overlong Basic credentials", async () => {
    const res = await tokenRequest(
      { grant_type: "client_credentials", scope: "api.read", resource: RESOURCE },
      basicAuth("c".repeat(129), SECRET),
    )

    expect(res.status).toBe(401)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_client")
  })

  it("rejects oversized and excessive form parameters", async () => {
    const oversized = await tokenRequest({
      grant_type: "client_credentials",
      client_id: SVC,
      client_secret: SECRET,
      scope: "s".repeat(4_097),
      resource: RESOURCE,
    })
    expect(oversized.status).toBe(400)
    expect((await oversized.json<{ error: string }>()).error).toBe("invalid_request")

    const excessive = new URLSearchParams({ grant_type: "client_credentials" })
    for (let parameter = 0; parameter < 32; parameter += 1) {
      excessive.set(`extra_${parameter}`, "x")
    }
    const excessiveResponse = await SELF.fetch(`${ISSUER}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: excessive.toString(),
    })
    expect(excessiveResponse.status).toBe(400)
    expect((await excessiveResponse.json<{ error: string }>()).error).toBe("invalid_request")

    const oversizedBody = await SELF.fetch(`${ISSUER}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `padding=${"x".repeat(65 * 1024)}`,
    })
    expect(oversizedBody.status).toBe(400)
    expect((await oversizedBody.json<{ error: string }>()).error).toBe("invalid_request")
  })

  it("issues a verifiable service token for a confidential client", async () => {
    // Given a confidential service client with a valid secret
    // When it requests a token via Basic auth
    const res = await tokenRequest(
      { grant_type: "client_credentials", scope: "api.read", resource: RESOURCE },
      basicAuth(SVC, SECRET),
    )
    // Then a Bearer service token is returned with no id/refresh token
    expect(res.status).toBe(200)
    expect(res.headers.get("cache-control")).toContain("no-store")
    const body = await res.json<{
      access_token: string
      token_type: string
      expires_in: number
      scope: string
      id_token?: string
      refresh_token?: string
    }>()
    expect(body.token_type).toBe("Bearer")
    expect(body.scope).toBe("api.read")
    expect(body.id_token).toBeUndefined()
    expect(body.refresh_token).toBeUndefined()

    // And the token verifies against the JWKS with service claims
    const jwks = createLocalJWKSet({ keys: [...(await getPublicJwks(env)).keys] })
    const { payload } = await jwtVerify(body.access_token, jwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    })
    expect(payload.sub).toBe(`client:${SVC}`)
    expect(payload.aud).toBe(RESOURCE)
    expect(payload["actor_type"]).toBe("service")
    expect(payload["token_use"]).toBe("access_token")
    expect(payload["client_id"]).toBe(SVC)
  })

  it("accepts client_secret_post authentication", async () => {
    const res = await tokenRequest({
      grant_type: "client_credentials",
      client_id: SVC,
      client_secret: SECRET,
      scope: "api.read",
      resource: RESOURCE,
    })
    expect(res.status).toBe(200)
  })

  it("rejects a wrong client secret with invalid_client", async () => {
    const res = await tokenRequest(
      { grant_type: "client_credentials", scope: "api.read", resource: RESOURCE },
      basicAuth(SVC, "wrong-secret"),
    )
    expect(res.status).toBe(401)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_client")
  })

  it("rejects a public client with unauthorized_client", async () => {
    const res = await tokenRequest({
      grant_type: "client_credentials",
      client_id: "pub_cc_test",
      scope: "api.read",
      resource: RESOURCE,
    })
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("unauthorized_client")
  })

  it("rejects user-context scopes", async () => {
    for (const scope of ["openid", "profile", "email", "groups", "offline_access"]) {
      const res = await tokenRequest(
        { grant_type: "client_credentials", scope, resource: RESOURCE },
        basicAuth(SVC, SECRET),
      )
      expect(res.status).toBe(400)
      expect((await res.json<{ error: string }>()).error).toBe("invalid_scope")
    }
  })

  it("rejects scopes outside the client's allowed set", async () => {
    const res = await tokenRequest(
      { grant_type: "client_credentials", scope: "admin.read", resource: RESOURCE },
      basicAuth(SVC, SECRET),
    )
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_scope")
  })

  it("rejects a scope allowed by the client but not by the resource", async () => {
    await env.DB.prepare(
      "UPDATE oauth_resources SET allowed_scopes_json = '[\"api.write\"]' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()
    const res = await tokenRequest(
      { grant_type: "client_credentials", scope: "api.read", resource: RESOURCE },
      basicAuth(SVC, SECRET),
    )
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_scope")
  })

  it("rejects an unpermitted resource with invalid_target", async () => {
    const res = await tokenRequest(
      { grant_type: "client_credentials", scope: "api.read", resource: "https://evil.example" },
      basicAuth(SVC, SECRET),
    )
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_target")
  })
})
