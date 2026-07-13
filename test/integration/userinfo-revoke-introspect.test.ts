import { env, SELF } from "cloudflare:test"
import { decodeJwt } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { saveConsent } from "../../src/db/queries/consents"
import { createUser } from "../../src/db/queries/users"
import { hashClientSecret } from "../../src/security/client-secret"
import { issueUserAccessToken } from "../../src/tokens/access-token"

const ISSUER = "https://auth.pangda.app"
const CLIENT = "pangda_app"
const REDIRECT = "https://app.pangda.app/auth/callback"
const RESOURCE = "https://api.pangda.app"
const SCOPE = "openid profile email groups offline_access api.read"
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
const SVC = "svc_internal_worker"
const SVC_SECRET = "introspect-secret-abc123xyz"

let sessionToken = ""
let userId = ""

beforeEach(async () => {
  await Promise.all([
    env.RATE_LIMIT.getByName("oauth:introspect:ip:unknown").reset(),
    env.RATE_LIMIT.getByName("oauth:userinfo:ip:unknown").reset(),
  ])
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
  ])
  const user = await createUser(env, {
    email: "bob@pangda.app",
    name: "Bob",
    userType: "internal",
    emailVerified: true,
  })
  userId = user.id
  const session = await createSession(env, {
    userId: user.id,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  sessionToken = session.token
  await saveConsent(env, { userId: user.id, clientId: CLIENT, scope: SCOPE, resource: RESOURCE })
  await env.DB.prepare("UPDATE oauth_clients SET client_secret_hash = ? WHERE client_id = ?")
    .bind(await hashClientSecret(SVC_SECRET), SVC)
    .run()
})

type Tokens = { access_token: string; refresh_token: string; id_token: string }

async function obtainTokens(scope = SCOPE): Promise<Tokens> {
  const url = new URL(`${ISSUER}/oauth/authorize`)
  const params: Record<string, string> = {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE,
  }
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value)
  }
  const authRes = await SELF.fetch(url.toString(), {
    headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
    redirect: "manual",
  })
  const code = new URL(authRes.headers.get("location") ?? "").searchParams.get("code") ?? ""
  const tokenRes = await SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      client_id: CLIENT,
    }).toString(),
  })
  return tokenRes.json<Tokens>()
}

async function serviceToken(): Promise<string> {
  const res = await SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${SVC}:${SVC_SECRET}`)}`,
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api.read",
      resource: RESOURCE,
    }).toString(),
  })
  return (await res.json<{ access_token: string }>()).access_token
}

function post(path: string, body: Record<string, string>, authHeader?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" }
  if (authHeader !== undefined) {
    headers["authorization"] = authHeader
  }
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers,
    body: new URLSearchParams(body).toString(),
  })
}

describe("GET /oauth/userinfo", () => {
  it("returns user claims for a valid access token", async () => {
    const { access_token } = await obtainTokens()
    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${access_token}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json<{ sub: string; email: string; user_type: string }>()
    expect(body.sub).toBe(userId)
    expect(body.email).toBe("bob@pangda.app")
    expect(body.user_type).toBe("internal")
  })

  it("rejects a missing token with a 401 and WWW-Authenticate", async () => {
    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`)
    expect(res.status).toBe(401)
    expect(res.headers.get("www-authenticate")).toContain("Bearer")
  })

  it("rejects a service (client_credentials) token with 403", async () => {
    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${await serviceToken()}` },
    })
    expect(res.status).toBe(403)
  })

  it("rejects an ID token even though it has a valid server signature", async () => {
    const { id_token } = await obtainTokens()
    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${id_token}` },
    })
    expect(res.status).toBe(401)
    expect(res.headers.get("www-authenticate")).toContain("invalid_token")
  })

  it("withholds groups and user_type when the groups scope was not granted", async () => {
    const tokens = await obtainTokens("openid profile email api.read")
    expect(decodeJwt(tokens.access_token)["user_type"]).toBeUndefined()
    expect(decodeJwt(tokens.id_token)["groups"]).toBeUndefined()
    expect(decodeJwt(tokens.id_token)["user_type"]).toBeUndefined()

    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    })
    const body = await res.json<Record<string, unknown>>()
    expect(res.status).toBe(200)
    expect(body["groups"]).toBeUndefined()
    expect(body["user_type"]).toBeUndefined()
  })

  it("rejects an access token that was not issued for the OpenID UserInfo purpose", async () => {
    const { access_token } = await obtainTokens("profile email api.read")
    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${access_token}` },
    })
    expect(res.status).toBe(401)
  })

  it("rejects a signed access token with an unregistered audience", async () => {
    const issued = await issueUserAccessToken(env, {
      userId,
      clientId: CLIENT,
      resource: "https://unregistered.example",
      scope: "openid",
      userType: "internal",
    })
    const res = await SELF.fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${issued.token}` },
    })
    expect(res.status).toBe(401)
  })
})

describe("POST /oauth/revoke", () => {
  it("revokes a refresh token and blocks further use", async () => {
    const { refresh_token } = await obtainTokens()
    expect((await post("/oauth/revoke", { token: refresh_token, client_id: CLIENT })).status).toBe(
      200,
    )
    const reuse = await post("/oauth/token", {
      grant_type: "refresh_token",
      refresh_token,
      client_id: CLIENT,
    })
    expect(reuse.status).toBe(400)
  })

  it("returns 200 for an unknown token without probing", async () => {
    expect(
      (await post("/oauth/revoke", { token: "unknown-token", client_id: CLIENT })).status,
    ).toBe(200)
  })
})

describe("POST /oauth/introspect", () => {
  const svcAuth = `Basic ${btoa(`${SVC}:${SVC_SECRET}`)}`

  it("reports an active access token with metadata", async () => {
    const { access_token } = await obtainTokens()
    const res = await post("/oauth/introspect", { token: access_token }, svcAuth)
    expect(res.status).toBe(200)
    const body = await res.json<{ active: boolean; sub: string; client_id: string }>()
    expect(body.active).toBe(true)
    expect(body.sub).toBe(userId)
    expect(body.client_id).toBe(CLIENT)
  })

  it("reports an active refresh token", async () => {
    const { refresh_token } = await obtainTokens()
    const body = await (await post("/oauth/introspect", { token: refresh_token }, svcAuth)).json<{
      active: boolean
      token_type: string
    }>()
    expect(body.active).toBe(true)
    expect(body.token_type).toBe("refresh_token")
  })

  it("reports inactive for a garbage token", async () => {
    const body = await (await post("/oauth/introspect", { token: "not-real" }, svcAuth)).json<{
      active: boolean
    }>()
    expect(body.active).toBe(false)
  })

  it("reports an ID token as inactive", async () => {
    const { id_token } = await obtainTokens()
    const body = await (await post("/oauth/introspect", { token: id_token }, svcAuth)).json<{
      active: boolean
    }>()
    expect(body.active).toBe(false)
  })

  it("reports a valid access token outside the introspector's audiences as inactive", async () => {
    const issued = await issueUserAccessToken(env, {
      userId,
      clientId: CLIENT,
      resource: "https://app.pangda.app",
      scope: "openid app.read",
      userType: "internal",
    })
    const body = await (await post("/oauth/introspect", { token: issued.token }, svcAuth)).json<{
      active: boolean
    }>()
    expect(body.active).toBe(false)
  })

  it("rejects introspection by a public client", async () => {
    const res = await post("/oauth/introspect", { token: "x", client_id: CLIENT })
    expect(res.status).toBe(403)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_client")
  })

  it("applies the IP breaker before parsing or authenticating the request", async () => {
    const limiter = env.RATE_LIMIT.getByName("oauth:introspect:ip:unknown")
    for (let attempt = 0; attempt < 120; attempt += 1) {
      expect((await limiter.check(120, 300)).allowed).toBe(true)
    }

    const blocked = await SELF.fetch(`${ISSUER}/oauth/introspect`, { method: "POST" })
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0)
    expect((await blocked.json<{ error: string }>()).error).toBe("temporarily_unavailable")
  })
})
