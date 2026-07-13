import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { createMagicLink } from "../../src/auth/magic-link"
import { createUser } from "../../src/db/queries/users"

const ISSUER = "https://auth.pangda.app"
const EMAIL = "mona@pangda.app"

let userId = ""

beforeEach(async () => {
  await env.RATE_LIMIT.getByName("capability:magic:ip:unknown").reset()
  await env.DB.batch([env.DB.prepare("DELETE FROM sessions"), env.DB.prepare("DELETE FROM users")])
  const user = await createUser(env, { email: EMAIL, name: "Mona", userType: "external" })
  userId = user.id
})

function cookieValue(setCookies: readonly string[], name: string): string | null {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? null
    }
  }
  return null
}

function callback(token: string): Promise<Response> {
  return SELF.fetch(`${ISSUER}/login/magic/callback?token=${token}`, { redirect: "manual" })
}

async function confirmMagicLink(token: string): Promise<Response> {
  const confirmation = await callback(token)
  expect(confirmation.status).toBe(200)
  expect(await confirmation.text()).toContain("Confirm sign in")
  expect(cookieValue(confirmation.headers.getSetCookie(), "__Host-keyforge_session")).toBeNull()

  const csrf = cookieValue(confirmation.headers.getSetCookie(), "__Host-keyforge_csrf") ?? ""
  expect(csrf).not.toBe("")
  return SELF.fetch(`${ISSUER}/login/magic/callback`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ token, csrf_token: csrf }).toString(),
    redirect: "manual",
  })
}

async function requestMagicLink(email: string): Promise<Response> {
  const getRes = await SELF.fetch(`${ISSUER}/login/magic`)
  const csrf = cookieValue(getRes.headers.getSetCookie(), "__Host-keyforge_csrf") ?? ""
  return SELF.fetch(`${ISSUER}/login/magic`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ email, csrf_token: csrf }).toString(),
  })
}

describe("magic link login", () => {
  it("consumes a valid link and authenticates a session", async () => {
    const { token } = await createMagicLink(env, { userId, email: EMAIL, redirectTo: "/" })
    const peek = await callback(token)
    expect(peek.status).toBe(200)
    expect(await peek.text()).toContain("Confirm sign in")

    const res = await confirmMagicLink(token)
    expect(res.status).toBe(302)
    const session = cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session")
    expect(session).not.toBeNull()

    const home = await SELF.fetch(`${ISSUER}/`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(home.status).toBe(200)
    expect(await home.text()).toContain(EMAIL)
  })

  it("consumes a link exactly once", async () => {
    const { token } = await createMagicLink(env, { userId, email: EMAIL, redirectTo: "/" })
    expect((await confirmMagicLink(token)).status).toBe(302)
    expect((await callback(token)).status).toBe(400)
  })

  it("rejects an invalid token", async () => {
    expect((await callback("not-a-real-token")).status).toBe(400)
  })

  it("rate limits valid-shaped callback probes before token lookup", async () => {
    const limiter = env.RATE_LIMIT.getByName("capability:magic:ip:unknown")
    for (let attempt = 0; attempt < 60; attempt += 1) {
      expect((await limiter.check(60, 300)).allowed).toBe(true)
    }

    const blocked = await callback("a".repeat(43))
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0)
  })

  it("shows a generic sent page for both known and unknown emails", async () => {
    const known = await requestMagicLink(EMAIL)
    expect(known.status).toBe(200)
    expect(await known.text()).toContain("Check your email")

    const unknown = await requestMagicLink("nobody@pangda.app")
    expect(unknown.status).toBe(200)
    expect(await unknown.text()).toContain("Check your email")
  })
})
