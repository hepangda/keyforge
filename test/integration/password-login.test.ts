import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { setUserPassword } from "../../src/auth/password"
import { createUser } from "../../src/db/queries/users"
import { requestCorrelationHash } from "../../src/security/request-meta"

const ISSUER = "https://auth.pangda.app"
const EMAIL = "alice@pangda.app"
const PASSWORD = "correct horse battery staple"

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM password_credentials"),
    env.DB.prepare("DELETE FROM users"),
  ])
  const accountHash = await requestCorrelationHash(env, "login-account", EMAIL)
  await Promise.all([
    env.RATE_LIMIT.getByName(`login:ip-account:unknown:${accountHash}`).reset(),
    env.RATE_LIMIT.getByName(`login:account:${accountHash}`).reset(),
    env.RATE_LIMIT.getByName("login:ip:unknown").reset(),
  ])
  const user = await createUser(env, {
    email: EMAIL,
    name: "Alice",
    userType: "internal",
    emailVerified: true,
  })
  await setUserPassword(env, user.id, PASSWORD)
})

function cookieValue(setCookies: readonly string[], name: string): string | null {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      const value = cookie.slice(name.length + 1).split(";")[0]
      return value ?? null
    }
  }
  return null
}

async function getCsrf(): Promise<{ token: string; cookieHeader: string }> {
  const res = await SELF.fetch(`${ISSUER}/login`)
  const token = cookieValue(res.headers.getSetCookie(), "__Host-keyforge_csrf")
  if (token === null) {
    throw new Error("login page did not issue a CSRF cookie")
  }
  return { token, cookieHeader: `__Host-keyforge_csrf=${token}` }
}

async function postLogin(fields: Record<string, string>, cookieHeader?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" }
  if (cookieHeader !== undefined) {
    headers["cookie"] = cookieHeader
  }
  return SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers,
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  })
}

describe("password login + session", () => {
  it("serves the login form and issues a CSRF cookie", async () => {
    const res = await SELF.fetch(`${ISSUER}/login`)
    expect(res.status).toBe(200)
    expect(await res.text()).toContain("Sign in to KeyForge")
    expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-keyforge_csrf="))).toBe(true)
    expect(res.headers.get("content-security-policy")).toContain("script-src 'self'")
    expect(res.headers.get("content-security-policy")).not.toContain("script-src 'unsafe-inline'")
    expect(res.headers.get("permissions-policy")).toContain("camera=()")
  })

  it("logs in with correct credentials and authenticates the session", async () => {
    const { token, cookieHeader } = await getCsrf()
    const res = await postLogin(
      { email: EMAIL, password: PASSWORD, csrf_token: token, return_to: "/" },
      cookieHeader,
    )
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/")
    const session = cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session")
    expect(session).not.toBeNull()

    const home = await SELF.fetch(`${ISSUER}/`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(home.status).toBe(200)
    expect(await home.text()).toContain(EMAIL)
  })

  it("rejects a wrong password with 401 and no session cookie", async () => {
    const { token, cookieHeader } = await getCsrf()
    const res = await postLogin(
      { email: EMAIL, password: "wrong-password", csrf_token: token },
      cookieHeader,
    )
    expect(res.status).toBe(401)
    expect(cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session")).toBeNull()
  })

  it("rejects a POST with a missing/invalid CSRF token", async () => {
    const res = await postLogin({ email: EMAIL, password: PASSWORD })
    expect(res.status).toBe(403)
  })

  it("logs out and server-side revokes the session", async () => {
    const { token, cookieHeader } = await getCsrf()
    const loginRes = await postLogin(
      { email: EMAIL, password: PASSWORD, csrf_token: token },
      cookieHeader,
    )
    const session = cookieValue(loginRes.headers.getSetCookie(), "__Host-keyforge_session")
    const sessionCookie = `__Host-keyforge_session=${session}`
    const confirmation = await SELF.fetch(`${ISSUER}/logout`, {
      headers: { cookie: sessionCookie },
    })
    expect(confirmation.status).toBe(200)
    expect(await confirmation.text()).toContain("Sign out?")
    const logoutCsrf = cookieValue(confirmation.headers.getSetCookie(), "__Host-keyforge_csrf")
    expect(logoutCsrf).not.toBeNull()
    if (logoutCsrf === null) return

    const logout = await SELF.fetch(`${ISSUER}/logout`, {
      method: "POST",
      headers: {
        cookie: `${sessionCookie}; __Host-keyforge_csrf=${logoutCsrf}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ csrf_token: logoutCsrf }).toString(),
      redirect: "manual",
    })
    expect(logout.status).toBe(302)

    const home = await SELF.fetch(`${ISSUER}/`, {
      headers: { cookie: sessionCookie },
      redirect: "manual",
    })
    expect(home.status).toBe(302)
    expect(home.headers.get("location")).toBe("/login")
  })

  it("rate limits login once the per-identity threshold is exceeded", async () => {
    const accountHash = await requestCorrelationHash(env, "login-account", EMAIL)
    const limiter = env.RATE_LIMIT.getByName(`login:ip-account:unknown:${accountHash}`)
    for (let hit = 0; hit < 9; hit += 1) {
      await limiter.check(10, 300)
    }
    const { token, cookieHeader } = await getCsrf()
    const finalAllowed = await postLogin(
      { email: EMAIL, password: "wrong-password", csrf_token: token },
      cookieHeader,
    )
    expect(finalAllowed.status).toBe(401)
    const res = await postLogin(
      { email: EMAIL, password: "wrong-password", csrf_token: token },
      cookieHeader,
    )
    expect(res.status).toBe(429)
    expect(res.headers.get("retry-after")).not.toBeNull()
  })

  it("rate limits one IP even when an attacker rotates account identifiers", async () => {
    const limiter = env.RATE_LIMIT.getByName("login:ip:unknown")
    const rotatedHash = await requestCorrelationHash(env, "login-account", "missing-two@pangda.app")
    const fineLimiter = env.RATE_LIMIT.getByName(`login:ip-account:unknown:${rotatedHash}`)
    await fineLimiter.reset()
    for (let hit = 0; hit < 49; hit += 1) {
      await limiter.check(50, 300)
    }
    const { token, cookieHeader } = await getCsrf()
    const finalAllowed = await postLogin(
      { email: "missing-one@pangda.app", password: "wrong-password", csrf_token: token },
      cookieHeader,
    )
    expect(finalAllowed.status).toBe(401)

    const blocked = await postLogin(
      { email: "missing-two@pangda.app", password: "wrong-password", csrf_token: token },
      cookieHeader,
    )
    expect(blocked.status).toBe(429)
    expect(blocked.headers.get("retry-after")).not.toBeNull()
    expect(await fineLimiter.check(10, 300)).toMatchObject({ allowed: true, remaining: 9 })
  })
})
