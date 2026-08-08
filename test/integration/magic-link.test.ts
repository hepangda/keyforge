import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { createMagicLink } from "../../src/auth/magic-link"
import { createSession, getSessionByToken, listSessionsByUser } from "../../src/auth/session"
import { createUser } from "../../src/db/queries/users"

const ISSUER = "https://auth.pangda.app"
const EMAIL = "mona@pangda.app"

let userId = ""

beforeEach(async () => {
  await env.RATE_LIMIT.getByName("capability:magic:ip:unknown").reset()
  await env.DB.batch([env.DB.prepare("DELETE FROM sessions"), env.DB.prepare("DELETE FROM users")])
  const user = await createUser(env, { email: EMAIL, name: "Mona" })
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
    const { token } = await createMagicLink(env, { userId, redirectTo: "/" })
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
  it("keeps an existing browser session when reauth magic opens elsewhere", async () => {
    const original = await createSession(env, {
      userId,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const { token } = await createMagicLink(env, {
      userId,
      redirectTo: "/?section=profile&flow=change-email",
      reauthenticate: true,
    })
    const response = await confirmMagicLink(token)
    expect(response.status).toBe(302)
    expect(await getSessionByToken(env, original.token)).not.toBeNull()
    expect(await listSessionsByUser(env, userId)).toHaveLength(2)
  })

  it("consumes a link exactly once", async () => {
    const { token } = await createMagicLink(env, { userId, redirectTo: "/" })
    expect((await confirmMagicLink(token)).status).toBe(302)
    expect((await callback(token)).status).toBe(400)
  })

  it("rejects an invalid token with a fresh-link action", async () => {
    const response = await callback("not-a-real-token")
    expect(response.status).toBe(400)
    const html = await response.text()
    expect(html).toContain('href="/login/magic"')
    expect(html).toContain("Sign in with email")
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
    await Promise.all([
      env.KV.delete(`test:email:${EMAIL}`),
      env.KV.delete("test:email:nobody@pangda.app"),
    ])
    const known = await requestMagicLink(EMAIL)
    expect(known.status).toBe(200)
    expect(await known.text()).toContain("Check your email")
    await expect.poll(() => env.KV.get(`test:email:${EMAIL}`)).not.toBeNull()

    const unknown = await requestMagicLink("nobody@pangda.app")
    expect(unknown.status).toBe(200)
    expect(await unknown.text()).toContain("Check your email")
    expect(await env.KV.get("test:email:nobody@pangda.app")).toBeNull()
  })
  it("preserves safe task state on request, error, and sent pages", async () => {
    const target = "/console/clients/new?step=access"
    const request = await SELF.fetch(
      `${ISSUER}/login/magic?reauth=1&return_to=${encodeURIComponent(target)}`,
    )
    const csrf = cookieValue(request.headers.getSetCookie(), "__Host-keyforge_csrf") ?? ""
    const requestHtml = await request.text()
    expect(requestHtml).toContain(`name="return_to" value="${target.replace("&", "&amp;")}"`)
    expect(requestHtml).toContain('name="reauth" value="1"')
    expect(requestHtml).toContain(
      `href="/login?return_to=${encodeURIComponent(target)}&amp;reauth=1"`,
    )

    const sent = await SELF.fetch(`${ISSUER}/login/magic`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `__Host-keyforge_csrf=${csrf}`,
      },
      body: new URLSearchParams({
        email: "nobody@pangda.app",
        csrf_token: csrf,
        return_to: target,
        reauth: "1",
      }).toString(),
    })
    const sentHtml = await sent.text()
    expect(sentHtml).toContain(`href="/login?return_to=${encodeURIComponent(target)}&amp;reauth=1"`)

    const unsafe = await SELF.fetch(
      `${ISSUER}/login/magic?return_to=${encodeURIComponent("//evil.example")}`,
    )
    expect(await unsafe.text()).not.toContain("evil.example")
  })
  it("retains bounded email and continuation after CSRF failure", async () => {
    const target = "/?section=login-methods&flow=add-passkey"
    const response = await SELF.fetch(`${ISSUER}/login/magic`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        email: "Draft.User@Example.test",
        return_to: target,
        reauth: "1",
      }).toString(),
    })
    expect(response.status).toBe(403)
    const html = await response.text()
    expect(html).toContain('value="draft.user@example.test"')
    expect(html).toContain(`name="return_to" value="${target.replace("&", "&amp;")}"`)
    expect(html).toContain('name="reauth" value="1"')
  })
  it("uses a trusted payload target for cancel and CSRF recovery", async () => {
    const target = "/oauth/authorize?client_id=pangda_app&state="
    const { token } = await createMagicLink(env, {
      userId,
      redirectTo: target,
      reauthenticate: true,
    })
    const confirmation = await callback(token)
    const confirmationHtml = await confirmation.text()
    const expectedHref =
      "/login?return_to=%2Foauth%2Fauthorize%3Fclient_id%3Dpangda_app%26state%3D&amp;reauth=1"
    expect(confirmationHtml).toContain(`href="${expectedHref}"`)

    const failed = await SELF.fetch(`${ISSUER}/login/magic/callback`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token }).toString(),
    })
    expect(failed.status).toBe(403)
    expect(await failed.text()).toContain(`href="${expectedHref}"`)
  })

  it("refuses to mint a link after the user no longer exists", async () => {
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run()
    await expect(createMagicLink(env, { userId, redirectTo: "/" })).rejects.toThrow(
      "account unavailable",
    )
  })
})
