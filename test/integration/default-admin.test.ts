import { env, SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { verifyUserPassword } from "../../src/auth/password"
import { getUserByEmail, getUserGroupNames } from "../../src/db/queries/users"

const ISSUER = "https://auth.pangda.app"
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

  it("can sign in with the isolated test credentials and reach the admin API", async () => {
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

    const adminApi = await SELF.fetch(`${ISSUER}/admin/users`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(adminApi.status).toBe(200)
  })
})
