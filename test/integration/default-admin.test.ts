import { env, SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { getUserByEmail, getUserGroupNames } from "../../src/db/queries/users"
import { verifyPassword } from "../../src/security/crypto"

const ISSUER = "https://auth.pangda.app"
const SEED_HASH =
  "scrypt$32768$8$1$yVLhH6oa6f3is1oUx0mLCg$iev7MtM5HU75bcTn8fv3AVGHeTZQg4sx-AlPLAWHJMA"

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

describe("test-only administrator fixture", () => {
  it("has a password hash that verifies for 'admin' and rejects others", async () => {
    expect(await verifyPassword("admin", SEED_HASH)).toBe(true)
    expect(await verifyPassword("wrong", SEED_HASH)).toBe(false)
  })

  it("is seeded as an internal user in the admins group", async () => {
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    if (admin === null) {
      return
    }
    expect(admin.userType).toBe("internal")
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
      body: new URLSearchParams({ email: "admin", password: "admin", csrf_token: csrf }).toString(),
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
