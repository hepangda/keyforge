import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { createUser } from "../../src/db/queries/users"

const ISSUER = "https://auth.pangda.app"

beforeEach(async () => {
  await Promise.all([
    env.RATE_LIMIT.getByName("capability:social:ip:unknown").reset(),
    env.RATE_LIMIT.getByName("social-begin:ip:unknown").reset(),
  ])
})

function cookieValue(response: Response, name: string): string {
  const raw = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  return raw?.split(";")[0]?.slice(name.length + 1) ?? ""
}

async function beginIdentityLink(userId: string): Promise<{
  sessionToken: string
  sessionId: string
  state: string
  stateCookie: string
}> {
  const session = await createSession(env, {
    userId,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  const sessionCookie = `__Host-keyforge_session=${session.token}`
  const page = await SELF.fetch(`${ISSUER}/`, { headers: { cookie: sessionCookie } })
  const csrfToken = cookieValue(page, "__Host-keyforge_csrf")
  expect(csrfToken).not.toBe("")
  const response = await SELF.fetch(`${ISSUER}/account/identities/github/connect`, {
    method: "POST",
    headers: {
      cookie: `${sessionCookie}; __Host-keyforge_csrf=${csrfToken}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ csrf_token: csrfToken }).toString(),
    redirect: "manual",
  })
  expect(response.status).toBe(302)
  const state = new URL(response.headers.get("location") ?? "").searchParams.get("state") ?? ""
  const stateCookie = cookieValue(response, "__Host-keyforge_social")
  expect(state).not.toBe("")
  expect(stateCookie).toBe(state)
  return { sessionToken: session.token, sessionId: session.sessionId, state, stateCookie }
}

describe("social login authorize redirect", () => {
  it("redirects GitHub sign-in to GitHub with PKCE + state", async () => {
    const res = await SELF.fetch(`${ISSUER}/login/github`, { redirect: "manual" })
    expect(res.status).toBe(302)
    const location = new URL(res.headers.get("location") ?? "")
    expect(location.origin).toBe("https://github.com")
    expect(location.searchParams.get("client_id")).toBe("test-github-id")
    expect(location.searchParams.get("code_challenge_method")).toBe("S256")
    expect(location.searchParams.get("code_challenge")).toBeTruthy()
    expect(location.searchParams.get("state")).toBeTruthy()
    expect(location.searchParams.get("redirect_uri")).toBe(`${ISSUER}/login/github/callback`)
    const stateCookie = cookieValue(res, "__Host-keyforge_social")
    expect(stateCookie).toBe(location.searchParams.get("state"))
    expect(stateCookie).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it("rate limits social flow creation before storing one-time state", async () => {
    const limiter = env.RATE_LIMIT.getByName("social-begin:ip:unknown")
    for (let attempt = 0; attempt < 30; attempt += 1) {
      expect((await limiter.check(30, 300)).allowed).toBe(true)
    }

    const blocked = await SELF.fetch(`${ISSUER}/login/github`, { redirect: "manual" })
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0)
    expect(cookieValue(blocked, "__Host-keyforge_social")).toBe("")
  })

  it("redirects Google sign-in to Google with openid scope", async () => {
    const res = await SELF.fetch(`${ISSUER}/login/google`, { redirect: "manual" })
    expect(res.status).toBe(302)
    const location = new URL(res.headers.get("location") ?? "")
    expect(location.origin).toBe("https://accounts.google.com")
    expect(location.searchParams.get("scope")).toContain("openid")
  })

  it("404s an unknown provider", async () => {
    const res = await SELF.fetch(`${ISSUER}/login/facebook`, { redirect: "manual" })
    expect(res.status).toBe(404)
  })

  it("rejects a callback with a missing/invalid state", async () => {
    const res = await SELF.fetch(`${ISSUER}/login/github/callback?code=x&state=y`, {
      redirect: "manual",
    })
    expect(res.status).toBe(400)
  })

  it("rejects malformed matching state before one-time-token storage access", async () => {
    const state = "x".repeat(4_096)
    const res = await SELF.fetch(
      `${ISSUER}/login/github/callback?code=x&state=${encodeURIComponent(state)}`,
      {
        headers: { cookie: `__Host-keyforge_social=${state}` },
        redirect: "manual",
      },
    )

    expect(res.status).toBe(400)
  })

  it("rate limits valid-shaped callback probes before consuming state", async () => {
    const limiter = env.RATE_LIMIT.getByName("capability:social:ip:unknown")
    for (let attempt = 0; attempt < 60; attempt += 1) {
      expect((await limiter.check(60, 300)).allowed).toBe(true)
    }
    const state = "a".repeat(43)
    const res = await SELF.fetch(`${ISSUER}/login/github/callback?code=x&state=${state}`, {
      headers: { cookie: `__Host-keyforge_social=${state}` },
      redirect: "manual",
    })

    expect(res.status).toBe(429)
    expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0)
    expect(
      res.headers.getSetCookie().some((value) => value.startsWith("__Host-keyforge_social=")),
    ).toBe(false)
  })

  it("rechecks recent authentication before consuming a social identity link", async () => {
    const user = await createUser(env, { email: "social-link-stale@pangda.app" })
    const flow = await beginIdentityLink(user.id)
    await env.DB.prepare("UPDATE sessions SET auth_time = 0 WHERE id = ?")
      .bind(flow.sessionId)
      .run()

    const callbackUrl = `${ISSUER}/login/github/callback?code=x&state=${encodeURIComponent(flow.state)}`
    const callback = await SELF.fetch(callbackUrl, {
      headers: {
        cookie: `__Host-keyforge_session=${flow.sessionToken}; __Host-keyforge_social=${flow.stateCookie}`,
      },
      redirect: "manual",
    })
    expect(callback.status).toBe(403)
    expect(
      (
        await env.DB.prepare("SELECT COUNT(*) AS n FROM identities WHERE user_id = ?")
          .bind(user.id)
          .first<{ n: number }>()
      )?.n,
    ).toBe(0)

    const replay = await SELF.fetch(callbackUrl, {
      headers: {
        cookie: `__Host-keyforge_session=${flow.sessionToken}; __Host-keyforge_social=${flow.stateCookie}`,
      },
      redirect: "manual",
    })
    expect(replay.status).toBe(400)
  })

  it("binds identity linking to the exact session that started it", async () => {
    const user = await createUser(env, { email: "social-link-session@pangda.app" })
    const flow = await beginIdentityLink(user.id)
    const replacement = await createSession(env, {
      userId: user.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })

    const callback = await SELF.fetch(
      `${ISSUER}/login/github/callback?code=x&state=${encodeURIComponent(flow.state)}`,
      {
        headers: {
          cookie: `__Host-keyforge_session=${replacement.token}; __Host-keyforge_social=${flow.stateCookie}`,
        },
        redirect: "manual",
      },
    )
    expect(callback.status).toBe(403)
  })
})
