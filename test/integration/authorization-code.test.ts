import { env, SELF } from "cloudflare:test"
import { createLocalJWKSet, jwtVerify } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { saveConsent } from "../../src/db/queries/consents"
import { createUser } from "../../src/db/queries/users"
import { getPublicJwks } from "../../src/tokens/key-rotation"

const ISSUER = "https://auth.pangda.app"
const CLIENT = "pangda_app"
const REDIRECT = "https://app.pangda.app/auth/callback"
const RESOURCE = "https://api.pangda.app"
const SCOPE = "openid profile email groups offline_access api.read"
// RFC 7636 Appendix B reference PKCE pair.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

let sessionToken = ""
let userId = ""

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
  ])
  await env.DB.prepare(
    `UPDATE oauth_resources
     SET allowed_scopes_json = '["openid","profile","email","groups","offline_access","api.read","api.write"]'
     WHERE resource_uri = ?`,
  )
    .bind(RESOURCE)
    .run()
  const user = await createUser(env, {
    email: "alice@pangda.app",
    alias: "alice",
    name: "Alice",
    emailVerified: true,
  })
  userId = user.id
  await env.DB.prepare(
    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_employees', unixepoch())",
  )
    .bind(user.id)
    .run()
  const session = await createSession(env, {
    userId: user.id,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  sessionToken = session.token
  await saveConsent(env, { userId: user.id, clientId: CLIENT, scope: SCOPE, resource: RESOURCE })
})

function authorizeUrl(overrides: Record<string, string> = {}): string {
  const url = new URL(`${ISSUER}/oauth/authorize`)
  const params: Record<string, string> = {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: SCOPE,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE,
    ...overrides,
  }
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value)
  }
  return url.toString()
}

function authedFetch(url: string): Promise<Response> {
  return SELF.fetch(url, {
    headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
    redirect: "manual",
  })
}

function tokenRequest(body: Record<string, string>): Promise<Response> {
  return SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  })
}

async function obtainCode(overrides: Record<string, string> = {}): Promise<string> {
  const res = await authedFetch(authorizeUrl(overrides))
  const location = res.headers.get("location")
  if (location === null) {
    throw new Error(`authorize did not redirect (status ${res.status})`)
  }
  const code = new URL(location).searchParams.get("code")
  if (code === null) {
    throw new Error(`no code in redirect: ${location}`)
  }
  return code
}

function exchange(code: string, overrides: Record<string, string> = {}): Promise<Response> {
  return tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT,
    code_verifier: VERIFIER,
    client_id: CLIENT,
    ...overrides,
  })
}

describe("authorization_code + PKCE flow", () => {
  it("issues verifiable id, access, and refresh tokens", async () => {
    const authRes = await authedFetch(authorizeUrl({ state: "state-xyz", nonce: "nonce-abc" }))
    expect(authRes.status).toBe(302)
    const redirect = new URL(authRes.headers.get("location") ?? "")
    expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT)
    expect(redirect.searchParams.get("state")).toBe("state-xyz")
    const code = redirect.searchParams.get("code") ?? ""
    expect(code).not.toBe("")

    const res = await exchange(code)
    expect(res.status).toBe(200)
    const body = await res.json<{
      access_token: string
      id_token: string
      refresh_token: string
      token_type: string
    }>()
    expect(body.token_type).toBe("Bearer")
    expect(body.id_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()

    const jwks = createLocalJWKSet({ keys: [...(await getPublicJwks(env)).keys] })
    const { payload: id } = await jwtVerify(body.id_token, jwks, {
      issuer: ISSUER,
      audience: CLIENT,
    })
    expect(id.sub).toBe(userId)
    expect(id["nonce"]).toBe("nonce-abc")
    expect(id["email"]).toBe("alice@pangda.app")
    expect(id["preferred_username"]).toBe("alice")
    expect(id["groups"]).toContain("employees")

    const { payload: at } = await jwtVerify(body.access_token, jwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    })
    expect(at.sub).toBe(userId)
    expect(at["azp"]).toBe(CLIENT)
    expect(at["client_id"]).toBe(CLIENT)
    expect(at["token_use"]).toBe("access_token")
  })

  it("consumes an authorization code exactly once", async () => {
    const code = await obtainCode()
    expect((await exchange(code)).status).toBe(200)
    const second = await exchange(code)
    expect(second.status).toBe(400)
    expect((await second.json<{ error: string }>()).error).toBe("invalid_grant")
  })

  it("rejects a token exchange with a wrong code_verifier", async () => {
    const code = await obtainCode()
    const res = await exchange(code, { code_verifier: "a".repeat(43) })
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_grant")

    // A failed binding check must not burn a legitimate one-time code.
    expect((await exchange(code)).status).toBe(200)
  })

  it("renders an error page for an unregistered redirect_uri", async () => {
    const res = await authedFetch(authorizeUrl({ redirect_uri: "https://evil.example/cb" }))
    expect(res.status).toBe(400)
    expect(res.headers.get("content-security-policy")).toContain("form-action 'self';")
    expect(res.headers.get("content-security-policy")).not.toContain("https://evil.example")
    expect(await res.text()).toContain("Invalid redirect_uri")
  })

  it("rejects duplicated authorization parameters without trusting an ambiguous client", async () => {
    const ambiguousClient = new URL(authorizeUrl())
    ambiguousClient.searchParams.append("client_id", "pangda_admin")
    const page = await authedFetch(ambiguousClient.toString())
    expect(page.status).toBe(400)
    expect(page.headers.get("location")).toBeNull()

    const ambiguousScope = new URL(authorizeUrl())
    ambiguousScope.searchParams.append("scope", "openid")
    const redirected = await authedFetch(ambiguousScope.toString())
    expect(redirected.status).toBe(302)
    expect(new URL(redirected.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "invalid_request",
    )
  })

  it("rejects oversized authorization parameters before client lookup", async () => {
    const url = new URL(authorizeUrl())
    url.searchParams.set("client_id", `pangda_app${"x".repeat(128)}`)
    const response = await authedFetch(url.toString())

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
    expect(await response.text()).not.toContain("pangda_app")
  })

  it("rejects malformed reauthentication proofs before continuation lookup", async () => {
    const url = new URL(authorizeUrl())
    url.searchParams.set("_keyforge_reauth", "x".repeat(4_096))
    const response = await authedFetch(url.toString())

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it("rejects duplicated token request parameters", async () => {
    const code = await obtainCode()
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      client_id: CLIENT,
    })
    body.append("client_id", CLIENT)
    const response = await SELF.fetch(`${ISSUER}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    })
    expect(response.status).toBe(400)
    expect((await response.json<{ error: string }>()).error).toBe("invalid_request")

    // Parsing failure happened before code validation, so the code remains usable.
    expect((await exchange(code)).status).toBe(200)
  })

  it("rejects a scope allowed by the client but not by the target resource", async () => {
    const res = await authedFetch(
      authorizeUrl({ resource: "https://app.pangda.app", scope: "api.read" }),
    )
    expect(res.status).toBe(302)
    const redirect = new URL(res.headers.get("location") ?? "")
    expect(redirect.searchParams.get("error")).toBe("invalid_scope")
  })

  it("does not reuse consent granted for a different resource", async () => {
    const res = await authedFetch(
      authorizeUrl({ resource: "https://app.pangda.app", scope: "openid profile" }),
    )
    expect(res.status).toBe(200)
    expect(await res.text()).toContain("Authorize Pangda App")
  })

  it("rechecks resource scope policy when exchanging an authorization code", async () => {
    const code = await obtainCode()
    await env.DB.prepare(
      "UPDATE oauth_resources SET allowed_scopes_json = '[\"api.write\"]' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()
    const res = await exchange(code)
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_scope")
  })

  it("redirects unauthenticated authorize requests to login", async () => {
    const res = await SELF.fetch(authorizeUrl(), { redirect: "manual" })
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("/login")
  })
})

describe("refresh_token rotation + reuse detection", () => {
  it("rotates the refresh token and revokes the family on reuse", async () => {
    const first = await (await exchange(await obtainCode())).json<{ refresh_token: string }>()
    const rt1 = first.refresh_token

    const rotatedRes = await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: rt1,
      client_id: CLIENT,
    })
    expect(rotatedRes.status).toBe(200)
    const rotated = await rotatedRes.json<{ refresh_token: string }>()
    const rt2 = rotated.refresh_token
    expect(rt2).not.toBe(rt1)

    const reuse = await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: rt1,
      client_id: CLIENT,
    })
    expect(reuse.status).toBe(400)
    expect((await reuse.json<{ error: string }>()).error).toBe("invalid_grant")

    const afterReuse = await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: rt2,
      client_id: CLIENT,
    })
    expect(afterReuse.status).toBe(400)
  })
})
