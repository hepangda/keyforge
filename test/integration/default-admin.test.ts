import { env, SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { verifyUserPassword } from "../../src/auth/password"
import { ADMIN_API } from "../../src/config"
import { getUserByEmail, getUserGroupNames } from "../../src/db/queries/users"
import { issueUserAccessToken } from "../../src/tokens/access-token"

const ISSUER = "https://auth.pangda.app"

function authorization(token: string): string {
  return ["Bearer", token].join(" ")
}

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

describe("test-only administrator fixture", () => {
  it("has an administrator-eligible password and rejects others", async () => {
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    expect(await verifyUserPassword(env, admin?.id ?? "", "test-admin-password-2026")).toBe(true)
    expect(await verifyUserPassword(env, admin?.id ?? "", "wrong")).toBe(false)
  })

  it("is seeded in the admins group with a username", async () => {
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    if (admin === null) {
      return
    }
    expect(admin.alias).toMatch(/^[A-Za-z0-9]+$/)
    expect(await getUserGroupNames(env, admin.id)).toContain("admins")
  })

  it("can sign in and obtain administrator API authority", async () => {
    const page = await SELF.fetch(`${ISSUER}/login`)
    const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf")
    const login = await SELF.fetch(`${ISSUER}/login`, {
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
    expect(login.status).toBe(302)
    const session = cookieValue(login.headers.getSetCookie(), "__Host-keyforge_session")
    expect(session).not.toBe("")

    expect(
      (
        await SELF.fetch(`${ISSUER}/admin/users`, {
          headers: { cookie: `__Host-keyforge_session=${session}` },
        })
      ).status,
    ).toBe(401)

    const admin = await getUserByEmail(env, "admin")
    const accessToken = await issueUserAccessToken(env, {
      userId: admin?.id ?? "missing",
      clientId: "pangda_admin",
      resource: ADMIN_API.audience,
      scope: ADMIN_API.readScope,
    })
    const adminApi = await SELF.fetch(`${ISSUER}/admin/users`, {
      headers: { authorization: authorization(accessToken.token) },
    })
    expect(adminApi.status).toBe(200)
  })
})
