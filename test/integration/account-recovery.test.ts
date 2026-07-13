import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import {
  createEmailVerificationToken,
  createPasswordResetToken,
} from "../../src/auth/account-tokens"
import {
  setUserPassword,
  setUserPasswordAtSecurityVersion,
  verifyUserPassword,
} from "../../src/auth/password"
import { createSession } from "../../src/auth/session"
import { createUser, getUserById, getUserSecurityVersion } from "../../src/db/queries/users"
import { issueRefreshToken } from "../../src/tokens/refresh-token"

const ISSUER = "https://auth.pangda.app"
const EMAIL = "recover@pangda.app"

function cookieValue(response: Response, name: string): string {
  const raw = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  return raw?.split(";")[0]?.slice(name.length + 1) ?? ""
}

async function csrfPage(path: string, cookie?: string): Promise<{ token: string; cookie: string }> {
  const response = await SELF.fetch(`${ISSUER}${path}`, {
    ...(cookie === undefined ? {} : { headers: { cookie } }),
  })
  expect(response.status).toBe(200)
  const token = cookieValue(response, "__Host-keyforge_csrf")
  expect(token).not.toBe("")
  return { token, cookie: `__Host-keyforge_csrf=${token}` }
}

function postForm(path: string, fields: Record<string, string>, cookie: string): Promise<Response> {
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: {
      cookie,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  })
}

beforeEach(async () => {
  await env.RATE_LIMIT.getByName("capability:account-recovery:ip:unknown").reset()
  await env.DB.batch([
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM email_verifications"),
    env.DB.prepare("DELETE FROM password_reset_tokens"),
    env.DB.prepare("DELETE FROM password_credentials"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
  ])
  await env.KV.delete(`test:email:${EMAIL}`)
  await env.KV.delete("test:email:missing@pangda.app")
})

describe("account recovery", () => {
  it("rejects malformed capability tokens before account-token storage access", async () => {
    const response = await SELF.fetch(
      `${ISSUER}/password/reset?token=${encodeURIComponent("x".repeat(4_096))}`,
    )

    expect(response.status).toBe(400)
    expect(await response.text()).toContain("invalid, expired, or already used")
  })

  it("delivers a password reset without exposing whether an account exists", async () => {
    await createUser(env, { email: EMAIL, name: "Recover", emailVerified: true })
    const csrf = await csrfPage("/password/forgot")
    const known = await postForm(
      "/password/forgot",
      { email: EMAIL, csrf_token: csrf.token },
      csrf.cookie,
    )
    expect(known.status).toBe(200)
    expect(await known.text()).toContain("If an account exists")

    await expect
      .poll(() => env.KV.get(`test:email:${EMAIL}`, "json"))
      .toMatchObject({ to: EMAIL, subject: "Reset your KeyForge password" })
    const delivered = await env.KV.get(`test:email:${EMAIL}`, "json")
    expect(JSON.stringify(delivered)).toContain("/password/reset?token=")

    const missingCsrf = await csrfPage("/password/forgot")
    const missing = await postForm(
      "/password/forgot",
      { email: "missing@pangda.app", csrf_token: missingCsrf.token },
      missingCsrf.cookie,
    )
    expect(missing.status).toBe(200)
    expect(await missing.text()).toContain("If an account exists")
    expect(await env.KV.get("test:email:missing@pangda.app")).toBeNull()
  })

  it("resets a password once and revokes existing sessions", async () => {
    const user = await createUser(env, { email: EMAIL, name: "Recover" })
    await setUserPassword(env, user.id, "old password that is long")
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
    const { token } = await createPasswordResetToken(env, user.id, user.email)
    const csrf = await csrfPage(`/password/reset?token=${encodeURIComponent(token)}`)
    const result = await postForm(
      "/password/reset",
      {
        token,
        password: "new password that is even longer",
        password_confirm: "new password that is even longer",
        csrf_token: csrf.token,
      },
      csrf.cookie,
    )
    expect(result.status).toBe(200)
    expect(await result.text()).toContain("Password reset")
    expect(await verifyUserPassword(env, user.id, "new password that is even longer")).toBe(true)

    const oldSession = await SELF.fetch(`${ISSUER}/`, {
      headers: { cookie: `__Host-keyforge_session=${session.token}` },
      redirect: "manual",
    })
    expect(oldSession.status).toBe(302)
    expect(oldSession.headers.get("location")).toBe("/login")
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
    expect((await SELF.fetch(`${ISSUER}/password/reset?token=${token}`)).status).toBe(400)
  })

  it("rolls back the password, security epoch, and session mirrors if D1 revocation fails", async () => {
    const user = await createUser(env, { email: "reset-atomic@pangda.app" })
    const oldPassword = "old atomic password is long enough"
    const newPassword = "new atomic password is long enough"
    await setUserPassword(env, user.id, oldPassword)
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
      `CREATE TRIGGER test_block_reset_refresh
       BEFORE UPDATE OF revoked_at ON refresh_tokens
       BEGIN SELECT RAISE(ABORT, 'blocked refresh revocation'); END`,
    ).run()
    try {
      await expect(
        setUserPasswordAtSecurityVersion(env, user.id, newPassword, expectedSecurityVersion),
      ).rejects.toThrow()
    } finally {
      await env.DB.prepare("DROP TRIGGER IF EXISTS test_block_reset_refresh").run()
    }

    expect(await verifyUserPassword(env, user.id, oldPassword)).toBe(true)
    expect(await verifyUserPassword(env, user.id, newPassword)).toBe(false)
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

  it("invalidates an issued password-reset capability after a password security change", async () => {
    const user = await createUser(env, { email: EMAIL, name: "Recover" })
    await setUserPassword(env, user.id, "first password that is long enough")
    const { token } = await createPasswordResetToken(env, user.id, user.email)

    await setUserPassword(env, user.id, "second password that is long enough")

    const stale = await SELF.fetch(`${ISSUER}/password/reset?token=${encodeURIComponent(token)}`)
    expect(stale.status).toBe(400)
    expect(await stale.text()).toContain("invalid, expired, or already used")
  })

  it("verifies an email address with a single-use link", async () => {
    const user = await createUser(env, { email: EMAIL, emailVerified: false })
    const { token } = await createEmailVerificationToken(env, user.id, user.email)

    const confirmation = await SELF.fetch(
      `${ISSUER}/account/email/verify?token=${encodeURIComponent(token)}`,
    )
    expect(confirmation.status).toBe(200)
    expect(await confirmation.text()).toContain("Verify your email")
    expect((await getUserById(env, user.id))?.emailVerified).toBe(false)

    const secondConfirmation = await SELF.fetch(
      `${ISSUER}/account/email/verify?token=${encodeURIComponent(token)}`,
    )
    expect(secondConfirmation.status).toBe(200)
    const csrfToken = cookieValue(secondConfirmation, "__Host-keyforge_csrf")
    expect(csrfToken).not.toBe("")

    const verified = await postForm(
      "/account/email/verify",
      { token, csrf_token: csrfToken },
      `__Host-keyforge_csrf=${csrfToken}`,
    )
    expect(verified.status).toBe(200)
    expect(await verified.text()).toContain("Email verified")
    expect((await getUserById(env, user.id))?.emailVerified).toBe(true)
    expect(
      (await SELF.fetch(`${ISSUER}/account/email/verify?token=${encodeURIComponent(token)}`))
        .status,
    ).toBe(400)
  })

  it("rejects recovery form submissions without the double-submit token", async () => {
    const response = await postForm("/password/forgot", { email: EMAIL }, "")
    expect(response.status).toBe(403)
  })
})
