import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import {
  addUserPassword,
  listPasswordCredentials,
  setUserPassword,
  verifyLoginPassword,
} from "../../src/auth/password"
import { createSession, getSessionByToken, listSessionsByUser } from "../../src/auth/session"
import {
  createUser,
  getGroupByName,
  getUserByEmail,
  setUserGroups,
} from "../../src/db/queries/users"
import { requestCorrelationHash } from "../../src/security/request-meta"

const ISSUER = "https://auth.pangda.app"
const EMAIL = "alice@pangda.app"
const ALIAS = "alice-dev_1"
const PASSWORD = "correct horse battery staple"
const REGISTERED_REDIRECT = "https://app.pangda.app/auth/callback"

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM password_credentials"),
    env.DB.prepare("DELETE FROM users"),
  ])
  const accountHash = await requestCorrelationHash(env, "login-account", EMAIL)
  const aliasHash = await requestCorrelationHash(env, "login-account", ALIAS)
  await Promise.all([
    env.RATE_LIMIT.getByName(`login:ip-account:unknown:${accountHash}`).reset(),
    env.RATE_LIMIT.getByName(`login:account:${accountHash}`).reset(),
    env.RATE_LIMIT.getByName(`login:ip-account:unknown:${aliasHash}`).reset(),
    env.RATE_LIMIT.getByName(`login:account:${aliasHash}`).reset(),
    env.RATE_LIMIT.getByName("login:ip:unknown").reset(),
  ])
  const user = await createUser(env, {
    email: EMAIL,
    alias: ALIAS,
    name: "Alice",
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
    const policy = res.headers.get("content-security-policy")
    expect(policy).toContain(
      "script-src 'self' https://static.cloudflareinsights.com/beacon.min.js https://static.cloudflareinsights.com/beacon.min.js/;",
    )
    expect(policy).not.toContain("script-src 'unsafe-inline'")
    expect(res.headers.get("permissions-policy")).toContain("camera=()")
  })
  it("preserves only safe task state through alternate recovery links", async () => {
    const target = "/console/users/new?view=profile"
    const page = await SELF.fetch(
      `${ISSUER}/login?reauth=1&return_to=${encodeURIComponent(target)}`,
    )
    const html = await page.text()
    expect(html).toContain(
      `href="/password/forgot?return_to=${encodeURIComponent(target)}&amp;reauth=1"`,
    )
    expect(html).toContain(
      `href="/login/magic?return_to=${encodeURIComponent(target)}&amp;reauth=1"`,
    )

    const unsafe = await SELF.fetch(
      `${ISSUER}/login?reauth=1&return_to=${encodeURIComponent("https://evil.example/task")}`,
    )
    const unsafeHtml = await unsafe.text()
    expect(unsafeHtml).toContain('name="return_to" value="/"')
    expect(unsafeHtml).not.toContain("evil.example")
  })

  it("shows why reauthentication is required and preserves that context after errors", async () => {
    const target = "/?section=login-methods&flow=add-passkey"
    const page = await SELF.fetch(
      `${ISSUER}/login?reauth=1&hint=add_passkey&return_to=${encodeURIComponent(target)}`,
    )
    const html = await page.text()
    expect(html).toContain("Adding a passkey to your account requires a fresh sign-in.")
    expect(html).toContain('name="hint" value="add_passkey"')
    expect(html).toContain(
      `href="/login/magic?return_to=${encodeURIComponent(target)}&amp;reauth=1&amp;hint=add_passkey"`,
    )
    const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf") ?? ""
    const failed = await postLogin(
      {
        email: EMAIL,
        password: "wrong password",
        csrf_token: csrf,
        return_to: target,
        reauth: "1",
        hint: "add_passkey",
      },
      `__Host-keyforge_csrf=${csrf}`,
    )
    expect(await failed.text()).toContain(
      "Adding a passkey to your account requires a fresh sign-in.",
    )
  })

  it("allows only a registered OAuth callback through the login form redirect chain", async () => {
    const registeredReturnTo = `/oauth/authorize?${new URLSearchParams({
      client_id: "pangda_app",

      redirect_uri: REGISTERED_REDIRECT,
    })}`
    const registered = await SELF.fetch(
      `${ISSUER}/login?return_to=${encodeURIComponent(registeredReturnTo)}`,
    )
    expect(registered.headers.get("content-security-policy")).toContain(
      "form-action 'self' https://app.pangda.app;",
    )

    const unregisteredReturnTo = `/oauth/authorize?${new URLSearchParams({
      client_id: "pangda_app",
      redirect_uri: "https://evil.example/callback",
    })}`
    const unregistered = await SELF.fetch(
      `${ISSUER}/login?return_to=${encodeURIComponent(unregisteredReturnTo)}`,
    )
    expect(unregistered.headers.get("content-security-policy")).toContain("form-action 'self';")
    expect(unregistered.headers.get("content-security-policy")).not.toContain(
      "https://evil.example",
    )
  })
  it("replaces the previous browser session during password reauthentication", async () => {
    const previousUser = await createUser(env, { email: "previous-browser@pangda.app" })
    const previous = await createSession(env, {
      userId: previousUser.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const target = "/console/users/new"
    const page = await SELF.fetch(
      `${ISSUER}/login?reauth=1&return_to=${encodeURIComponent(target)}`,
      { headers: { cookie: `__Host-keyforge_session=${previous.token}` } },
    )
    const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf") ?? ""
    const response = await postLogin(
      {
        email: EMAIL,
        password: PASSWORD,
        csrf_token: csrf,
        return_to: target,
        reauth: "1",
      },
      `__Host-keyforge_session=${previous.token}; __Host-keyforge_csrf=${csrf}`,
    )
    expect(response.status).toBe(302)
    expect(await getSessionByToken(env, previous.token)).toBeNull()
    const nextToken = cookieValue(response.headers.getSetCookie(), "__Host-keyforge_session")
    expect(nextToken).not.toBeNull()
    const user = await getUserByEmail(env, EMAIL)
    expect(user).not.toBeNull()
    expect(await listSessionsByUser(env, user?.id ?? "missing")).toHaveLength(1)
  })

  it("does not expose the retired social login endpoints", async () => {
    for (const path of [
      "/login/github",
      "/login/google",
      "/login/github/callback",
      "/login/google/callback",
    ]) {
      expect((await SELF.fetch(`${ISSUER}${path}`)).status).toBe(404)
    }
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

  it("accepts hyphens and underscores in the username login identifier", async () => {
    const { token, cookieHeader } = await getCsrf()
    const res = await postLogin(
      { email: "ALICE-DEV_1", password: PASSWORD, csrf_token: token, return_to: "/" },
      cookieHeader,
    )
    expect(res.status).toBe(302)
    expect(cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session")).not.toBeNull()
  })

  it("supports a six-character password and multiple named passwords", async () => {
    const user = await getUserByEmail(env, EMAIL)
    expect(user).not.toBeNull()
    if (user === null) return
    await setUserPassword(env, user.id, "abc123", "Primary")
    expect(await addUserPassword(env, user.id, "backup7", "Backup")).not.toBeNull()
    expect((await listPasswordCredentials(env, user.id)).map((item) => item.name)).toEqual([
      "Primary",
      "Backup",
    ])
    expect(await verifyLoginPassword(env, user.id, "abc123")).toBe(true)
    expect(await verifyLoginPassword(env, user.id, "backup7")).toBe(true)
  }, 15_000)

  it("does not allow an administrator to use a short password", async () => {
    const user = await getUserByEmail(env, EMAIL)
    const admins = await getGroupByName(env, "admins")
    expect(user).not.toBeNull()
    expect(admins).not.toBeNull()
    if (user === null || admins === null) return
    await setUserPassword(env, user.id, "abc123", "Short before promotion")
    await setUserGroups(env, user.id, [admins.id])
    expect(await verifyLoginPassword(env, user.id, "abc123")).toBe(false)
    expect(await addUserPassword(env, user.id, "short7", "Rejected")).toBeNull()
    expect(
      await addUserPassword(env, user.id, "administrator-safe", "Admin password"),
    ).not.toBeNull()
    expect(await verifyLoginPassword(env, user.id, "administrator-safe")).toBe(true)
  }, 15_000)

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
