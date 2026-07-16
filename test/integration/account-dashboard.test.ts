import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { listPasswordCredentials } from "../../src/auth/password"
import { getSessionByToken, listSessionsByUser, revokeSessionById } from "../../src/auth/session"
import { getConsent, saveConsent } from "../../src/db/queries/consents"
import { recordAuthorizationGrant } from "../../src/db/queries/grants"
import { getUserByEmail } from "../../src/db/queries/users"
import { issueRefreshToken } from "../../src/tokens/refresh-token"

const ISSUER = "https://auth.pangda.app"

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM sessions"),
  ])
  await env.RATE_LIMIT.getByName("login:unknown:admin").reset()
})

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

async function login(): Promise<string> {
  const page = await SELF.fetch(`${ISSUER}/login`)
  const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf")
  const res = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({
      email: "admin",
      password: "test-admin-password-2026",
      csrf_token: csrf,
    }).toString(),
    redirect: "manual",
  })
  return cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session")
}

async function freshCsrf(sessionToken: string): Promise<string> {
  const res = await SELF.fetch(`${ISSUER}/`, {
    headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
  })
  return cookieValue(res.headers.getSetCookie(), "__Host-keyforge_csrf")
}

async function postAccount(path: string, sessionToken: string, csrf: string): Promise<Response> {
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_session=${sessionToken}; __Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ csrf_token: csrf }).toString(),
    redirect: "manual",
  })
}

async function issueForSession(sessionToken: string, clientId = "cloudflare_one") {
  const session = await getSessionByToken(env, sessionToken)
  if (session === null) {
    throw new Error("test session missing")
  }
  return issueRefreshToken(env, {
    userId: session.userId,
    clientId,
    sessionId: session.id,
    resource: "urn:pangda:cloudflare-one",
    scope: "openid profile email",
    authTime: session.authTime,
    rememberMe: false,
  })
}

async function expectFamilyRevoked(familyId: string, revoked: boolean): Promise<void> {
  const row = await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
    .bind(familyId)
    .first<{ revoked_at: number | null }>()
  expect(row).not.toBeNull()
  expect(row?.revoked_at !== null).toBe(revoked)
  const state = await env.REFRESH_TOKEN_FAMILY.getByName(familyId).getState()
  expect(state?.revoked).toBe(revoked)
}

describe("account dashboard", () => {
  it("redirects to /login when signed out", async () => {
    const res = await SELF.fetch(`${ISSUER}/`, { redirect: "manual" })
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/login")
  })

  it("renders the dashboard with username and admin nav for an admin", async () => {
    const token = await login()
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    const res = await SELF.fetch(`${ISSUER}/`, {
      headers: { cookie: `__Host-keyforge_session=${token}` },
    })
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain("admin")
    expect(html).toContain("/logout")
    expect(html).toContain("section=admin")
    expect(html).toContain('<main class="shell-main">')
    expect(html).toContain('<h1 class="sr-only">Profile</h1>')
    expect(html).not.toContain("Connected accounts")
    expect(html).not.toContain("Account type")
    expect(html).toContain(admin?.id ?? "missing-user-id")
    expect(html).not.toContain("Exposed as sub in ID tokens")
    expect(html).not.toContain("Administrator only")
  })

  it("keeps passwords and passkeys together under Login methods", async () => {
    const token = await login()
    const cookie = `__Host-keyforge_session=${token}`
    const res = await SELF.fetch(`${ISSUER}/?section=login-methods`, {
      headers: { cookie },
    })
    const html = await res.text()
    expect(html).toContain("Login methods")
    expect(html).toContain("Choose one method to manage")
    expect(html).toContain("Add login method")
    expect(html).toContain("flow=choose-login-method")
    expect(html).not.toContain('action="/account/passwords"')
    expect(html).not.toContain("data-passkey-register")

    const chooser = await SELF.fetch(`${ISSUER}/?section=login-methods&flow=choose-login-method`, {
      headers: { cookie },
    })
    const chooserHtml = await chooser.text()
    expect(chooserHtml).toContain("Add a login method")
    expect(chooserHtml).toContain("flow=add-password")
    expect(chooserHtml).toContain("flow=add-passkey")

    const configure = await SELF.fetch(`${ISSUER}/?section=login-methods&flow=add-password`, {
      headers: { cookie },
    })
    const configureHtml = await configure.text()
    expect(configureHtml).toContain('action="/account/passwords"')
    expect(configureHtml).toContain("Verification happens when you submit")
    expect(configureHtml).not.toContain("Verify and continue")

    const passkey = await SELF.fetch(`${ISSUER}/?section=login-methods&flow=add-passkey`, {
      headers: { cookie },
    })
    expect(await passkey.text()).toContain("data-passkey-register")

    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    const password = admin === null ? undefined : (await listPasswordCredentials(env, admin.id))[0]
    expect(password).toBeDefined()
    const manage = await SELF.fetch(
      `${ISSUER}/?section=login-methods&flow=manage-password&credential=${password?.id ?? "missing"}`,
      { headers: { cookie } },
    )
    const manageHtml = await manage.text()
    expect(manageHtml).toContain(`/account/passwords/${password?.id ?? "missing"}/rename`)
    expect(manageHtml).toContain(`/account/passwords/${password?.id ?? "missing"}/delete`)
    expect(manageHtml).toContain("Verification happens when you submit")
  })

  it("keeps the username read-only in self-service profile flows", async () => {
    const token = await login()
    const res = await SELF.fetch(`${ISSUER}/?section=profile&flow=edit-profile`, {
      headers: { cookie: `__Host-keyforge_session=${token}` },
    })
    const html = await res.text()
    expect(html).toContain("Only an administrator can change your username")
    expect(html).toContain('name="name"')
    expect(html).not.toContain('name="alias"')
  })

  it("shows only the selected section on the right", async () => {
    const token = await login()
    const cookie = `__Host-keyforge_session=${token}`
    const sessions = await SELF.fetch(`${ISSUER}/?section=sessions`, { headers: { cookie } })
    const sessionsHtml = await sessions.text()
    expect(sessionsHtml).toContain("Devices and browsers currently signed in")
    expect(sessionsHtml).not.toContain("Your account identity and information")

    const profile = await SELF.fetch(`${ISSUER}/`, { headers: { cookie } })
    const profileHtml = await profile.text()
    expect(profileHtml).toContain("Review your identity, then choose one account detail")
    expect(profileHtml).not.toContain("Devices and browsers currently signed in")
  })

  it("exposes the admin console link only under the Administration section", async () => {
    const token = await login()
    const cookie = `__Host-keyforge_session=${token}`
    const adminSection = await SELF.fetch(`${ISSUER}/?section=admin`, { headers: { cookie } })
    expect(await adminSection.text()).toContain("/console")
    const defaultSection = await SELF.fetch(`${ISSUER}/`, { headers: { cookie } })
    expect(await defaultSection.text()).not.toContain("/console")
  })
})

describe("account session management", () => {
  it("signs out all other sessions but keeps the current one", async () => {
    const current = await login()
    const other = await login()
    const currentFamily = await issueForSession(current)
    const otherFamily = await issueForSession(other)
    expect(await getSessionByToken(env, current)).not.toBeNull()
    expect(await getSessionByToken(env, other)).not.toBeNull()

    const csrf = await freshCsrf(current)
    const res = await postAccount("/account/sessions/revoke-others", current, csrf)
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/?section=sessions&notice=sessions_revoked")

    expect(await getSessionByToken(env, current)).not.toBeNull()
    expect(await getSessionByToken(env, other)).toBeNull()
    await expectFamilyRevoked(currentFamily.familyId, false)
    await expectFamilyRevoked(otherFamily.familyId, true)
  })

  it("revokes a single session by id", async () => {
    const current = await login()
    const other = await login()
    const otherSession = await getSessionByToken(env, other)
    expect(otherSession).not.toBeNull()
    if (otherSession === null) {
      return
    }
    const otherFamily = await issueForSession(other)

    const csrf = await freshCsrf(current)
    const res = await postAccount(`/account/sessions/${otherSession.id}/revoke`, current, csrf)
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/?section=sessions&notice=session_revoked")

    expect(await getSessionByToken(env, other)).toBeNull()
    expect(await getSessionByToken(env, current)).not.toBeNull()
    await expectFamilyRevoked(otherFamily.familyId, true)
  })

  it("only revokes a session for its owner", async () => {
    const token = await login()
    const session = await getSessionByToken(env, token)
    expect(session).not.toBeNull()
    if (session === null) {
      return
    }
    expect(await revokeSessionById(env, session.id, "usr_not_the_owner")).toBe(false)
    expect(await getSessionByToken(env, token)).not.toBeNull()
    expect(await revokeSessionById(env, session.id, session.userId)).toBe(true)
    expect(await getSessionByToken(env, token)).toBeNull()
  })

  it("lists only the active sessions for a user", async () => {
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    if (admin === null) {
      return
    }
    const current = await login()
    await login()
    expect((await listSessionsByUser(env, admin.id)).length).toBe(2)

    const csrf = await freshCsrf(current)
    await postAccount("/account/sessions/revoke-others", current, csrf)
    expect((await listSessionsByUser(env, admin.id)).length).toBe(1)
  })
})

describe("account app access", () => {
  it("revokes an app's granted access", async () => {
    const token = await login()
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    if (admin === null) {
      return
    }
    await saveConsent(env, {
      userId: admin.id,
      clientId: "cloudflare_one",
      scope: "openid profile",
      resource: null,
    })
    const session = await getSessionByToken(env, token)
    if (session === null) {
      throw new Error("test session missing")
    }
    const family = await issueForSession(token)
    await recordAuthorizationGrant(env, {
      userId: admin.id,
      clientId: "cloudflare_one",
      sessionId: session.id,
      scope: "openid profile email",
      resource: "urn:pangda:cloudflare-one",
      grantType: "authorization_code",
    })
    expect(await getConsent(env, admin.id, "cloudflare_one")).not.toBeNull()

    const csrf = await freshCsrf(token)
    const res = await postAccount("/account/apps/cloudflare_one/revoke", token, csrf)
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/?section=apps&notice=app_revoked")
    expect(await getConsent(env, admin.id, "cloudflare_one")).toBeNull()
    await expectFamilyRevoked(family.familyId, true)
    const grant = await env.DB.prepare(
      "SELECT revoked_at FROM authorization_grants WHERE user_id = ? AND client_id = ?",
    )
      .bind(admin.id, "cloudflare_one")
      .first<{ revoked_at: number | null }>()
    expect(grant?.revoked_at).not.toBeNull()
  })

  it("ignores an account action with an invalid CSRF token", async () => {
    const token = await login()
    const admin = await getUserByEmail(env, "admin")
    if (admin === null) {
      throw new Error("seed admin missing")
    }
    await saveConsent(env, {
      userId: admin.id,
      clientId: "cloudflare_one",
      scope: "openid",
      resource: null,
    })
    const res = await SELF.fetch(`${ISSUER}/account/apps/cloudflare_one/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `__Host-keyforge_session=${token}`,
      },
      body: new URLSearchParams({ csrf_token: "bogus" }).toString(),
      redirect: "manual",
    })
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/?section=apps&notice=invalid")
    expect(await getConsent(env, admin.id, "cloudflare_one")).not.toBeNull()
  })

  it("requires authentication for account actions", async () => {
    const res = await SELF.fetch(`${ISSUER}/account/sessions/revoke-others`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf_token: "x" }).toString(),
      redirect: "manual",
    })
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("/login")
  })
})
