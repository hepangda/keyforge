import { env, SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { setUserPassword, verifyUserPassword } from "../../src/auth/password"
import { createSession } from "../../src/auth/session"
import {
  createUser,
  getUserByEmail,
  getUserById,
  getUserSecurityVersion,
  updateUserEmail,
} from "../../src/db/queries/users"
import { insertCredential, listCredentialSummaries } from "../../src/db/queries/webauthn"
import { issueRefreshToken } from "../../src/tokens/refresh-token"

const ISSUER = "https://auth.pangda.app"

function cookieValue(response: Response, name: string): string {
  const raw = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  return raw?.split(";")[0]?.slice(name.length + 1) ?? ""
}

async function authenticatedBrowser(userId: string): Promise<{
  sessionId: string
  sessionToken: string
  csrfToken: string
  cookie: string
}> {
  const session = await createSession(env, {
    userId,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  const sessionCookie = `__Host-keyforge_session=${session.token}`
  const page = await SELF.fetch(`${ISSUER}/`, { headers: { cookie: sessionCookie } })
  expect(page.status).toBe(200)
  const csrfToken = cookieValue(page, "__Host-keyforge_csrf")
  return {
    sessionId: session.sessionId,
    sessionToken: session.token,
    csrfToken,
    cookie: `${sessionCookie}; __Host-keyforge_csrf=${csrfToken}`,
  }
}

function postAccount(
  path: string,
  browser: { csrfToken: string; cookie: string },
  fields: Record<string, string> = {},
): Promise<Response> {
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: {
      cookie: browser.cookie,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ csrf_token: browser.csrfToken, ...fields }).toString(),
    redirect: "manual",
  })
}

describe("account security settings", () => {
  it("updates the profile and adds a second password without replacing the first", async () => {
    const user = await createUser(env, {
      email: "settings@pangda.app",
      name: "Before",
      emailVerified: true,
    })
    await setUserPassword(env, user.id, "old password with enough length")
    const browser = await authenticatedBrowser(user.id)
    const other = await createSession(env, {
      userId: user.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const currentRefresh = await issueRefreshToken(env, {
      userId: user.id,
      clientId: "pangda_app",
      sessionId: browser.sessionId,
      resource: "https://api.pangda.app",
      scope: "openid offline_access",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })
    const otherRefresh = await issueRefreshToken(env, {
      userId: user.id,
      clientId: "pangda_app",
      sessionId: other.sessionId,
      resource: "https://api.pangda.app",
      scope: "openid offline_access",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })

    expect(
      (
        await postAccount("/account/profile", browser, {
          alias: "settingsuser",
          name: "After",
        })
      ).headers.get("location"),
    ).toContain("profile_updated")
    expect((await getUserById(env, user.id))?.name).toBe("After")
    expect((await getUserById(env, user.id))?.alias).toBe("settingsuser")

    const changed = await postAccount("/account/passwords", browser, {
      name: "Backup password",
      current_password: "old password with enough length",
      password: "new password with enough length",
      password_confirm: "new password with enough length",
    })
    expect(changed.status).toBe(302)
    expect(changed.headers.get("location")).toContain("password_added")
    expect(await verifyUserPassword(env, user.id, "old password with enough length")).toBe(true)
    expect(await verifyUserPassword(env, user.id, "new password with enough length")).toBe(true)

    expect(
      (
        await SELF.fetch(`${ISSUER}/`, {
          headers: { cookie: `__Host-keyforge_session=${other.token}` },
          redirect: "manual",
        })
      ).status,
    ).toBe(200)
    expect(
      (
        await SELF.fetch(`${ISSUER}/`, {
          headers: { cookie: `__Host-keyforge_session=${browser.sessionToken}` },
        })
      ).status,
    ).toBe(200)
    const refreshRows = await env.DB.prepare(
      "SELECT id, revoked_at FROM refresh_tokens WHERE id IN (?, ?) ORDER BY id",
    )
      .bind(currentRefresh.familyId, otherRefresh.familyId)
      .all<{ id: string; revoked_at: number | null }>()
    expect(
      refreshRows.results.find((row) => row.id === currentRefresh.familyId)?.revoked_at,
    ).toBeNull()
    expect(
      refreshRows.results.find((row) => row.id === otherRefresh.familyId)?.revoked_at,
    ).toBeNull()
    expect(
      (await env.REFRESH_TOKEN_FAMILY.getByName(currentRefresh.familyId).getState())?.revoked,
    ).toBe(false)
    expect(
      (await env.REFRESH_TOKEN_FAMILY.getByName(otherRefresh.familyId).getState())?.revoked,
    ).toBe(false)
  }, 10_000)

  it("sends passwordless users through recoverable reauthentication for sensitive actions", async () => {
    const user = await createUser(env, {
      email: "passwordless-sensitive@pangda.app",
      emailVerified: true,
    })
    const browser = await authenticatedBrowser(user.id)
    await env.DB.prepare("UPDATE sessions SET auth_time = 0 WHERE user_id = ?").bind(user.id).run()

    for (const [path, fields, returnTo] of [
      [
        "/account/passwords",
        {
          password: "a new password with enough length",
          password_confirm: "a new password with enough length",
        },
        "/?section=login-methods",
      ],
      ["/account/email/change", { new_email: "passwordless-new@pangda.app" }, "/?section=profile"],
      ["/account/delete", { confirmation: user.email }, "/?section=profile"],
    ] as const) {
      const response = await postAccount(path, browser, fields)
      expect(response.status).toBe(302)
      const location = response.headers.get("location") ?? ""
      expect(location).toContain("/login?reauth=1")
      expect(new URL(location, ISSUER).searchParams.get("return_to")).toBe(returnTo)
    }
    expect(await getUserById(env, user.id)).not.toBeNull()
  })

  it("renames and removes credentials without allowing the final persistent method to vanish", async () => {
    const user = await createUser(env, { email: "credentials@pangda.app" })
    await insertCredential(env, {
      userId: user.id,
      credentialId: "credential-settings",
      publicKey: "cHVibGljLWtleQ",
      counter: 0,
      transports: ["internal"],
      name: "Old name",
    })
    const browser = await authenticatedBrowser(user.id)
    const credential = (await listCredentialSummaries(env, user.id))[0]
    expect(credential).toBeDefined()
    if (credential === undefined) return

    const blocked = await postAccount(`/account/passkeys/${credential.id}/delete`, browser)
    expect(blocked.headers.get("location")).toContain("last_login_method")

    await setUserPassword(env, user.id, "fallback password is long enough")
    const renamed = await postAccount(`/account/passkeys/${credential.id}/rename`, browser, {
      name: "Laptop passkey",
    })
    expect(renamed.headers.get("location")).toContain("passkey_renamed")
    expect((await listCredentialSummaries(env, user.id))[0]?.name).toBe("Laptop passkey")
    const removed = await postAccount(`/account/passkeys/${credential.id}/delete`, browser)
    expect(removed.headers.get("location")).toContain("passkey_deleted")
    expect(await listCredentialSummaries(env, user.id)).toHaveLength(0)
  })

  it("changes email only after confirming the new address and then revokes sessions", async () => {
    const user = await createUser(env, { email: "old-email@pangda.app", emailVerified: true })
    await setUserPassword(env, user.id, "email password is long enough")
    const browser = await authenticatedBrowser(user.id)
    const refresh = await issueRefreshToken(env, {
      userId: user.id,
      clientId: "pangda_cli",
      sessionId: null,
      resource: "https://api.pangda.app",
      scope: "openid offline_access api.read",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })
    const requested = await postAccount("/account/email/change", browser, {
      new_email: "new-email@pangda.app",
      current_password: "email password is long enough",
    })
    expect(requested.headers.get("location")).toContain("email_change_sent")
    expect((await getUserById(env, user.id))?.email).toBe("old-email@pangda.app")

    const email = await env.KV.get<{ text: string }>("test:email:new-email@pangda.app", "json")
    const token = email?.text.match(/email\/change\/verify\?token=([^\s]+)/)?.[1]
    expect(token).toBeTruthy()
    if (token === undefined) return

    const confirmation = await SELF.fetch(
      `${ISSUER}/account/email/change/verify?token=${encodeURIComponent(token)}`,
    )
    expect(confirmation.status).toBe(200)
    expect(await confirmation.text()).toContain("Confirm email change")
    expect((await getUserById(env, user.id))?.email).toBe("old-email@pangda.app")

    const csrfToken = cookieValue(confirmation, "__Host-keyforge_csrf")
    expect(csrfToken).not.toBe("")
    const confirmed = await postAccount(
      "/account/email/change/verify",
      { csrfToken, cookie: `__Host-keyforge_csrf=${csrfToken}` },
      { token },
    )
    expect(confirmed.status).toBe(200)
    expect(await confirmed.text()).toContain("Email address changed")
    expect((await getUserById(env, user.id))?.email).toBe("new-email@pangda.app")
    expect(
      (
        await SELF.fetch(`${ISSUER}/`, {
          headers: { cookie: `__Host-keyforge_session=${browser.sessionToken}` },
          redirect: "manual",
        })
      ).status,
    ).toBe(302)
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
          .bind(refresh.familyId)
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).not.toBeNull()
    expect((await env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId).getState())?.revoked).toBe(
      true,
    )
    expect(
      (await SELF.fetch(`${ISSUER}/account/email/change/verify?token=${encodeURIComponent(token)}`))
        .status,
    ).toBe(400)
  })

  it("rolls back an email change and session mirrors if D1 revocation fails", async () => {
    const user = await createUser(env, { email: "email-atomic-old@pangda.app" })
    await setUserPassword(env, user.id, "email atomic password is long enough")
    const expectedSecurityVersion = await getUserSecurityVersion(env, user.id)
    expect(expectedSecurityVersion).not.toBeNull()
    if (expectedSecurityVersion === null) return
    const session = await createSession(env, {
      userId: user.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const refresh = await issueRefreshToken(env, {
      userId: user.id,
      clientId: "pangda_cli",
      sessionId: null,
      resource: "https://api.pangda.app",
      scope: "openid offline_access api.read",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })
    await env.DB.prepare(
      `CREATE TRIGGER test_block_email_refresh
       BEFORE UPDATE OF revoked_at ON refresh_tokens
       BEGIN SELECT RAISE(ABORT, 'blocked refresh revocation'); END`,
    ).run()
    try {
      await expect(
        updateUserEmail(env, user.id, "email-atomic-new@pangda.app", expectedSecurityVersion),
      ).rejects.toThrow()
    } finally {
      await env.DB.prepare("DROP TRIGGER IF EXISTS test_block_email_refresh").run()
    }

    expect((await getUserById(env, user.id))?.email).toBe("email-atomic-old@pangda.app")
    expect(await getUserSecurityVersion(env, user.id)).toBe(expectedSecurityVersion)
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM sessions WHERE id = ?")
          .bind(session.sessionId)
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).toBeNull()
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
          .bind(refresh.familyId)
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).toBeNull()
    expect((await env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId).getState())?.revoked).toBe(
      false,
    )
  })

  it("deletes an ordinary account but protects the final active administrator", async () => {
    const user = await createUser(env, { email: "delete-me@pangda.app" })
    await setUserPassword(env, user.id, "delete password is long enough")
    const browser = await authenticatedBrowser(user.id)
    const deleted = await postAccount("/account/delete", browser, {
      confirmation: user.email,
      current_password: "delete password is long enough",
    })
    expect(deleted.headers.get("location")).toBe("/login?notice=account_deleted")
    expect(await getUserById(env, user.id)).toBeNull()

    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    if (admin === null) return
    const adminBrowser = await authenticatedBrowser(admin.id)
    const protectedResult = await postAccount("/account/delete", adminBrowser, {
      confirmation: admin.email,
      current_password: "test-admin-password-2026",
    })
    expect(protectedResult.headers.get("location")).toContain("last_active_admin")
    expect(await getUserById(env, admin.id)).not.toBeNull()
  })
})
