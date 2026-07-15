import { env, SELF } from "cloudflare:test"
import { createLocalJWKSet, jwtVerify } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { setUserPassword } from "../../src/auth/password"
import { createUser } from "../../src/db/queries/users"
import { getPublicJwks } from "../../src/tokens/key-rotation"

const ISSUER = "https://auth.pangda.app"
const EMAIL = "e2e-user@pangda.app"
const PASSWORD = "correct horse battery staple e2e"
const CLIENT = "pangda_app"
const REDIRECT = "https://app.pangda.app/auth/callback"
const RESOURCE = "https://api.pangda.app"
const SCOPE = "openid profile email groups offline_access api.read"
// RFC 7636 Appendix B reference PKCE pair.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

let userId = ""

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM password_credentials"),
    env.DB.prepare("DELETE FROM users"),
  ])
  const user = await createUser(env, {
    email: EMAIL,
    name: "E2E User",
    emailVerified: true,
  })
  userId = user.id
  await setUserPassword(env, user.id, PASSWORD)
  await env.DB.prepare(
    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_employees', unixepoch())",
  )
    .bind(user.id)
    .run()
  await env.RATE_LIMIT.getByName(`login:unknown:${EMAIL}`).reset()
})

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

function authorizeUrl(extra: Record<string, string> = {}): string {
  const url = new URL(`${ISSUER}/oauth/authorize`)
  const params: Record<string, string> = {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: SCOPE,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE,
    ...extra,
  }
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value)
  }
  return url.toString()
}

async function login(returnTo: string): Promise<{ session: string; location: string }> {
  const page = await SELF.fetch(`${ISSUER}/login`)
  const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf")
  const res = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({
      email: EMAIL,
      password: PASSWORD,
      csrf_token: csrf,
      return_to: returnTo,
    }).toString(),
    redirect: "manual",
  })
  return {
    session: cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session"),
    location: res.headers.get("location") ?? "",
  }
}

function postDecision(opts: {
  readonly session: string
  readonly csrf: string
  readonly decision: string
  readonly state?: string
  readonly nonce?: string
}): Promise<Response> {
  const params: Record<string, string> = {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: SCOPE,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE,
    decision: opts.decision,
    csrf_token: opts.csrf,
  }
  if (opts.state !== undefined) {
    params["state"] = opts.state
  }
  if (opts.nonce !== undefined) {
    params["nonce"] = opts.nonce
  }
  return SELF.fetch(`${ISSUER}/oauth/authorize/decision`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_session=${opts.session}; __Host-keyforge_csrf=${opts.csrf}`,
    },
    body: new URLSearchParams(params).toString(),
    redirect: "manual",
  })
}

describe("oauth login + callback (end to end)", () => {
  it("logs in, approves consent, receives a code at the callback, and exchanges it for tokens", async () => {
    const state = "state-e2e-123"
    const nonce = "nonce-e2e-456"

    // 1. A relying party sends the browser to /oauth/authorize while signed out;
    //    the server bounces to the login page, preserving the original request.
    const start = await SELF.fetch(authorizeUrl({ state, nonce }), { redirect: "manual" })
    expect(start.status).toBe(302)
    const loginLocation = start.headers.get("location") ?? ""
    expect(loginLocation).toContain("/login")
    const returnTo = new URL(loginLocation, ISSUER).searchParams.get("return_to") ?? ""
    expect(returnTo).toContain("/oauth/authorize")

    // 2. The user signs in with a password; a session is issued and we're sent back.
    const { session, location } = await login(returnTo)
    expect(session).not.toBe("")
    expect(location).toContain("/oauth/authorize")
    expect(location).toContain(`client_id=${CLIENT}`)

    // 3. Re-issuing the authorize request while signed in shows the consent page.
    const consent = await SELF.fetch(`${ISSUER}${returnTo}`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(consent.status).toBe(200)
    expect(await consent.text()).toContain("Pangda App")
    expect(consent.headers.get("content-security-policy")).toContain(
      "form-action 'self' https://app.pangda.app;",
    )
    const consentCsrf = cookieValue(consent.headers.getSetCookie(), "__Host-keyforge_csrf")
    expect(consentCsrf).not.toBe("")

    // 4. Approving consent redirects to the client's callback with the code + state.
    const decision = await postDecision({
      session,
      csrf: consentCsrf,
      decision: "approve",
      state,
      nonce,
    })
    expect(decision.status).toBe(302)
    const callback = new URL(decision.headers.get("location") ?? "")
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT)
    expect(callback.searchParams.get("state")).toBe(state)
    const code = callback.searchParams.get("code") ?? ""
    expect(code).not.toBe("")

    // 5. The client exchanges the authorization code for tokens at the token endpoint.
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
    expect(tokenRes.status).toBe(200)
    const tokens = await tokenRes.json<{
      token_type: string
      id_token: string
      access_token: string
      refresh_token: string
    }>()
    expect(tokens.token_type).toBe("Bearer")
    expect(tokens.access_token).toBeTruthy()
    expect(tokens.refresh_token).toBeTruthy()

    // 6. The id_token verifies against the published JWKS and carries the caller's claims.
    const jwks = createLocalJWKSet({ keys: [...(await getPublicJwks(env)).keys] })
    const { payload } = await jwtVerify(tokens.id_token, jwks, { issuer: ISSUER, audience: CLIENT })
    expect(payload.sub).toBe(userId)
    expect(payload["nonce"]).toBe(nonce)
    expect(payload["email"]).toBe(EMAIL)
  })

  it("sends access_denied back to the callback when the user rejects consent", async () => {
    const { session } = await login("/")
    expect(session).not.toBe("")

    const consent = await SELF.fetch(authorizeUrl({ state: "deny-state" }), {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(consent.status).toBe(200)
    const consentCsrf = cookieValue(consent.headers.getSetCookie(), "__Host-keyforge_csrf")

    const decision = await postDecision({
      session,
      csrf: consentCsrf,
      decision: "deny",
      state: "deny-state",
    })
    expect(decision.status).toBe(302)
    const callback = new URL(decision.headers.get("location") ?? "")
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT)
    expect(callback.searchParams.get("error")).toBe("access_denied")
    expect(callback.searchParams.get("state")).toBe("deny-state")
  })
})
