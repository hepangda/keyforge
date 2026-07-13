import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { setUserPassword } from "../../src/auth/password"
import { createSession, getSessionByToken } from "../../src/auth/session"
import { saveConsent } from "../../src/db/queries/consents"
import { createUser } from "../../src/db/queries/users"
import { issueIdToken } from "../../src/tokens/id-token"
import { issueRefreshToken } from "../../src/tokens/refresh-token"
import type { User } from "../../src/types/domain"

const ISSUER = "https://auth.pangda.app"
const CLIENT = "pangda_app"
const REDIRECT = "https://app.pangda.app/auth/callback"
const LOGOUT_REDIRECT = "https://app.pangda.app/"
const RESOURCE = "https://api.pangda.app"
const SCOPE = "openid profile"
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
const PASSWORD = "oidc interaction password"

let user: User
let sessionToken = ""
let sessionId = ""

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
  ])
  user = await createUser(env, {
    email: "oidc-interactions@pangda.app",
    name: "OIDC Interactions",
    userType: "internal",
    emailVerified: true,
  })
  await setUserPassword(env, user.id, PASSWORD)
  const session = await createSession(env, {
    userId: user.id,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  sessionToken = session.token
  sessionId = session.sessionId
})

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
    state: "interaction-state",
    ...extra,
  }
  for (const [name, value] of Object.entries(params)) {
    url.searchParams.set(name, value)
  }
  return url.toString()
}

function fetchWithSession(url: string): Promise<Response> {
  return SELF.fetch(url, {
    headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
    redirect: "manual",
  })
}

function cookieValue(response: Response, name: string): string {
  const raw = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  return raw?.split(";")[0]?.slice(name.length + 1) ?? ""
}

async function reauthenticate(login: URL): Promise<{ continuation: URL; sessionToken: string }> {
  const loginPage = await fetchWithSession(login.toString())
  expect(loginPage.status).toBe(200)
  expect(await loginPage.text()).toContain("Sign in again")
  const csrfToken = cookieValue(loginPage, "__Host-keyforge_csrf")
  expect(csrfToken).not.toBe("")

  const returnTo = login.searchParams.get("return_to") ?? ""
  const response = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      cookie: `__Host-keyforge_session=${sessionToken}; __Host-keyforge_csrf=${csrfToken}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      email: user.email,
      password: PASSWORD,
      return_to: returnTo,
      reauth: "1",
      csrf_token: csrfToken,
    }).toString(),
    redirect: "manual",
  })
  expect(response.status).toBe(302)
  const freshSessionToken = cookieValue(response, "__Host-keyforge_session")
  expect(freshSessionToken).not.toBe("")
  const continuation = new URL(response.headers.get("location") ?? "", ISSUER)
  expect(continuation.searchParams.get("_keyforge_reauth")).not.toBeNull()
  return { continuation, sessionToken: freshSessionToken }
}

function fetchWithToken(url: string, token: string): Promise<Response> {
  return SELF.fetch(url, {
    headers: { cookie: `__Host-keyforge_session=${token}` },
    redirect: "manual",
  })
}

async function confirmEndSession(url: URL): Promise<Response> {
  const confirmation = await fetchWithSession(url.toString())
  expect(confirmation.status).toBe(200)
  expect(await confirmation.text()).toContain("Sign out and continue")
  expect(await getSessionByToken(env, sessionToken)).not.toBeNull()

  const csrfToken = cookieValue(confirmation, "__Host-keyforge_csrf")
  expect(csrfToken).not.toBe("")
  const form = new URLSearchParams(url.searchParams)
  form.set("csrf_token", csrfToken)
  return SELF.fetch(`${ISSUER}/oauth/end_session`, {
    method: "POST",
    headers: {
      cookie: `__Host-keyforge_session=${sessionToken}; __Host-keyforge_csrf=${csrfToken}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
    redirect: "manual",
  })
}

function redirectParams(response: Response): URLSearchParams {
  return new URL(response.headers.get("location") ?? "", ISSUER).searchParams
}

describe("OIDC prompt and max_age", () => {
  it("returns login_required without interaction for prompt=none while signed out", async () => {
    const response = await SELF.fetch(authorizeUrl({ prompt: "none" }), {
      redirect: "manual",
    })

    expect(response.status).toBe(302)
    expect(redirectParams(response).get("error")).toBe("login_required")
    expect(redirectParams(response).get("state")).toBe("interaction-state")
  })

  it("returns consent_required without interaction when consent is missing", async () => {
    const response = await fetchWithSession(authorizeUrl({ prompt: "none" }))

    expect(response.status).toBe(302)
    expect(redirectParams(response).get("error")).toBe("consent_required")
  })

  it("forces the consent page even when prior consent covers the request", async () => {
    await saveConsent(env, {
      userId: user.id,
      clientId: CLIENT,
      scope: SCOPE,
      resource: RESOURCE,
    })

    const response = await fetchWithSession(authorizeUrl({ prompt: "consent" }))

    expect(response.status).toBe(200)
    expect(await response.text()).toContain("Authorize Pangda App")
  })

  it("preserves prompt=login until a real reauthentication proof is consumed", async () => {
    await saveConsent(env, {
      userId: user.id,
      clientId: CLIENT,
      scope: SCOPE,
      resource: RESOURCE,
    })
    const response = await fetchWithSession(authorizeUrl({ prompt: "login" }))

    expect(response.status).toBe(302)
    const login = new URL(response.headers.get("location") ?? "", ISSUER)
    expect(login.pathname).toBe("/login")
    expect(login.searchParams.get("reauth")).toBe("1")
    const returnTo = login.searchParams.get("return_to") ?? ""
    expect(new URL(returnTo, ISSUER).searchParams.get("prompt")).toBe("login")

    const withoutProof = await fetchWithSession(`${ISSUER}${returnTo}`)
    expect(new URL(withoutProof.headers.get("location") ?? "", ISSUER).pathname).toBe("/login")

    const reauthenticated = await reauthenticate(login)
    expect(reauthenticated.continuation.searchParams.get("prompt")).toBe("login")
    const continued = await fetchWithToken(
      reauthenticated.continuation.toString(),
      reauthenticated.sessionToken,
    )
    expect(continued.status).toBe(302)
    expect(redirectParams(continued).get("code")).not.toBeNull()
  })

  it("requires fresh authentication when max_age is exceeded", async () => {
    await saveConsent(env, {
      userId: user.id,
      clientId: CLIENT,
      scope: SCOPE,
      resource: RESOURCE,
    })
    await env.DB.prepare("UPDATE sessions SET auth_time = unixepoch() - 600 WHERE id = ?")
      .bind(sessionId)
      .run()

    const interactive = await fetchWithSession(authorizeUrl({ max_age: "60" }))
    expect(interactive.status).toBe(302)
    const login = new URL(interactive.headers.get("location") ?? "", ISSUER)
    expect(login.pathname).toBe("/login")
    const returnTo = new URL(login.searchParams.get("return_to") ?? "", ISSUER)
    expect(returnTo.searchParams.get("max_age")).toBe("60")

    const silent = await fetchWithSession(authorizeUrl({ max_age: "60", prompt: "none" }))
    expect(redirectParams(silent).get("error")).toBe("login_required")

    const reauthenticated = await reauthenticate(login)
    expect(reauthenticated.continuation.searchParams.get("max_age")).toBe("60")
    const continued = await fetchWithToken(
      reauthenticated.continuation.toString(),
      reauthenticated.sessionToken,
    )
    expect(continued.status).toBe(302)
    expect(redirectParams(continued).get("code")).not.toBeNull()
  })

  it("treats max_age=0 as fresh-login-required without creating a loop", async () => {
    await saveConsent(env, {
      userId: user.id,
      clientId: CLIENT,
      scope: SCOPE,
      resource: RESOURCE,
    })
    const response = await fetchWithSession(authorizeUrl({ max_age: "0" }))

    const login = new URL(response.headers.get("location") ?? "", ISSUER)
    expect(login.pathname).toBe("/login")
    const returnTo = login.searchParams.get("return_to") ?? ""
    expect(new URL(returnTo, ISSUER).searchParams.get("max_age")).toBe("0")

    const reauthenticated = await reauthenticate(login)
    expect(reauthenticated.continuation.searchParams.get("max_age")).toBe("0")
    const continued = await fetchWithToken(
      reauthenticated.continuation.toString(),
      reauthenticated.sessionToken,
    )
    expect(continued.status).toBe(302)
    expect(redirectParams(continued).get("code")).not.toBeNull()
  })

  it("rejects unsupported prompt values and malformed max_age", async () => {
    const badPrompt = await fetchWithSession(authorizeUrl({ prompt: "select_account" }))
    expect(redirectParams(badPrompt).get("error")).toBe("invalid_request")

    const badCombination = await fetchWithSession(authorizeUrl({ prompt: "none consent" }))
    expect(redirectParams(badCombination).get("error")).toBe("invalid_request")

    const badMaxAge = await fetchWithSession(authorizeUrl({ max_age: "-1" }))
    expect(redirectParams(badMaxAge).get("error")).toBe("invalid_request")
  })
})

describe("RP-Initiated Logout", () => {
  async function idToken(clientId = CLIENT): Promise<string> {
    return issueIdToken(env, {
      user,
      groups: [],
      clientId,
      scopes: ["openid"],
      authTime: Math.floor(Date.now() / 1000),
      nonce: null,
    })
  }

  it("validates the RP redirect, returns state, and cascades refresh revocation", async () => {
    const refresh = await issueRefreshToken(env, {
      userId: user.id,
      clientId: CLIENT,
      sessionId,
      resource: RESOURCE,
      scope: "openid offline_access",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })
    const url = new URL(`${ISSUER}/oauth/end_session`)
    url.searchParams.set("id_token_hint", await idToken())
    url.searchParams.set("post_logout_redirect_uri", LOGOUT_REDIRECT)
    url.searchParams.set("state", "logout-state")

    const response = await confirmEndSession(url)

    expect(response.status).toBe(302)
    const redirect = new URL(response.headers.get("location") ?? "")
    expect(`${redirect.origin}${redirect.pathname}`).toBe(LOGOUT_REDIRECT)
    expect(redirect.searchParams.get("state")).toBe("logout-state")
    expect(await getSessionByToken(env, sessionToken)).toBeNull()
    expect((await env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId).getState())?.revoked).toBe(
      true,
    )
  })

  it("accepts a registered redirect associated by client_id without a hint", async () => {
    const url = new URL(`${ISSUER}/oauth/end_session`)
    url.searchParams.set("client_id", CLIENT)
    url.searchParams.set("post_logout_redirect_uri", LOGOUT_REDIRECT)

    const response = await confirmEndSession(url)

    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toBe(LOGOUT_REDIRECT)
    expect(await getSessionByToken(env, sessionToken)).toBeNull()
  })

  it("rejects unregistered redirects before altering the session", async () => {
    const url = new URL(`${ISSUER}/oauth/end_session`)
    url.searchParams.set("client_id", CLIENT)
    url.searchParams.set("post_logout_redirect_uri", "https://evil.example/")

    const response = await fetchWithSession(url.toString())

    expect(response.status).toBe(400)
    expect(await getSessionByToken(env, sessionToken)).not.toBeNull()
  })

  it("rejects a client_id that does not match the id_token_hint audience", async () => {
    const url = new URL(`${ISSUER}/oauth/end_session`)
    url.searchParams.set("client_id", "pangda_admin")
    url.searchParams.set("id_token_hint", await idToken())
    url.searchParams.set("post_logout_redirect_uri", "https://admin.pangda.app/")

    const response = await fetchWithSession(url.toString())

    expect(response.status).toBe(400)
    expect(await getSessionByToken(env, sessionToken)).not.toBeNull()
  })
})
