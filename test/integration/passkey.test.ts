import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { createUser } from "../../src/db/queries/users"
import {
  deleteCredentialPreservingLoginMethod,
  getCredentialByCredentialId,
  getCredentialsByUser,
  insertCredential,
  listCredentialSummaries,
  updateCredentialCounter,
} from "../../src/db/queries/webauthn"

const ISSUER = "https://auth.pangda.app"

let sessionCookie = ""
let userId = ""

beforeEach(async () => {
  await Promise.all([
    env.RATE_LIMIT.getByName("passkey:unknown").reset(),
    env.RATE_LIMIT.getByName("passkey-verify:ip:unknown").reset(),
  ])
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM webauthn_credentials"),
    env.DB.prepare("DELETE FROM users"),
  ])
  const user = await createUser(env, {
    email: "passkey@pangda.app",
    alias: "passkeyuser",
    name: "Passkey",
  })
  userId = user.id
  sessionCookie = `__Host-keyforge_session=${(await createSession(env, { userId: user.id, authMethod: "password", ttlSeconds: 3600 })).token}`
})

function firstSetCookie(res: Response, name: string): string {
  return (
    res.headers
      .getSetCookie()
      .find((c) => c.startsWith(`${name}=`))
      ?.split(";")[0] ?? ""
  )
}

async function authenticatedCsrf(): Promise<{ cookie: string; token: string }> {
  const page = await SELF.fetch(`${ISSUER}/`, { headers: { cookie: sessionCookie } })
  const csrfCookie = firstSetCookie(page, "__Host-keyforge_csrf")
  const token = csrfCookie.slice(csrfCookie.indexOf("=") + 1)
  return { cookie: `${sessionCookie}; ${csrfCookie}`, token }
}

describe("passkey registration ceremony", () => {
  it("returns registration options and a ceremony cookie for a signed-in user", async () => {
    const csrf = await authenticatedCsrf()
    const res = await SELF.fetch(`${ISSUER}/webauthn/register/options`, {
      method: "POST",
      headers: { cookie: csrf.cookie, "x-keyforge-csrf": csrf.token },
    })
    expect(res.status).toBe(200)
    const body = await res.json<{ challenge: string; rp: { id: string }; user: { name: string } }>()
    expect(body.challenge).toBeTruthy()
    expect(body.rp.id).toBe("auth.pangda.app")
    expect(body.user.name).toBe("passkeyuser")
    expect(firstSetCookie(res, "__Host-keyforge_webauthn")).not.toBe("")
  })

  it("requires an authenticated session", async () => {
    const res = await SELF.fetch(`${ISSUER}/webauthn/register/options`, { method: "POST" })
    expect(res.status).toBe(401)
  })

  it("returns a recoverable reauthentication URL when the session is stale", async () => {
    const csrf = await authenticatedCsrf()
    await env.DB.prepare("UPDATE sessions SET auth_time = 0 WHERE user_id = ?").bind(userId).run()
    const res = await SELF.fetch(`${ISSUER}/webauthn/register/options`, {
      method: "POST",
      headers: { cookie: csrf.cookie, "x-keyforge-csrf": csrf.token },
    })
    expect(res.status).toBe(403)
    const body = await res.json<{ error: string; reauthenticate_url: string }>()
    expect(body.error).toBe("recent_authentication_required")
    expect(body.reauthenticate_url).toBe("/login?reauth=1&return_to=%2F%3Fsection%3Dlogin-methods")
  })

  it("rejects register verify without a valid challenge", async () => {
    const csrf = await authenticatedCsrf()
    const res = await SELF.fetch(`${ISSUER}/webauthn/register/verify`, {
      method: "POST",
      headers: {
        cookie: csrf.cookie,
        "content-type": "application/json",
        "x-keyforge-csrf": csrf.token,
      },
      body: JSON.stringify({ id: "x" }),
    })
    expect(res.status).toBe(400)
  })
})

describe("passkey authentication ceremony", () => {
  it("returns authentication options and a ceremony cookie", async () => {
    const res = await SELF.fetch(`${ISSUER}/webauthn/login/options`, { method: "POST" })
    expect(res.status).toBe(200)
    expect((await res.json<{ challenge: string }>()).challenge).toBeTruthy()
    expect(firstSetCookie(res, "__Host-keyforge_webauthn")).not.toBe("")
  })

  it("rejects login verify for an unknown credential (challenge consumed)", async () => {
    const opts = await SELF.fetch(`${ISSUER}/webauthn/login/options`, { method: "POST" })
    const cookie = firstSetCookie(opts, "__Host-keyforge_webauthn")
    const res = await SELF.fetch(`${ISSUER}/webauthn/login/verify`, {
      method: "POST",
      headers: { cookie, "content-type": "application/json" },
      body: JSON.stringify({
        id: "unknown-credential",
        rawId: "x",
        response: {},
        type: "public-key",
      }),
    })
    expect(res.status).toBe(400)
    expect((await res.json<{ verified: boolean }>()).verified).toBe(false)
  })

  it("rejects a malformed ceremony id before challenge storage access", async () => {
    const res = await SELF.fetch(`${ISSUER}/webauthn/login/verify`, {
      method: "POST",
      headers: {
        cookie: "__Host-keyforge_webauthn=not-a-valid-token!",
        "content-type": "application/json",
      },
      body: JSON.stringify({ id: "unknown" }),
    })

    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_challenge")
  })

  it("rate limits login verification before consuming a challenge", async () => {
    const limiter = env.RATE_LIMIT.getByName("passkey-verify:ip:unknown")
    for (let attempt = 0; attempt < 39; attempt += 1) {
      expect((await limiter.check(40, 300)).allowed).toBe(true)
    }
    const request = () =>
      SELF.fetch(`${ISSUER}/webauthn/login/verify`, {
        method: "POST",
        headers: {
          cookie: `__Host-keyforge_webauthn=${"a".repeat(22)}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ id: "unknown" }),
      })

    expect((await request()).status).toBe(400)
    const blocked = await request()
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0)
  })
})

describe("webauthn credential storage", () => {
  it("stores, looks up, and updates a credential counter", async () => {
    await insertCredential(env, {
      userId,
      credentialId: "cred-abc",
      publicKey: "cHVia2V5",
      counter: 0,
      transports: ["internal"],
      name: "Test Key",
    })
    const byUser = await getCredentialsByUser(env, userId)
    expect(byUser.length).toBe(1)
    expect(byUser[0]?.transports).toContain("internal")
    expect((await getCredentialByCredentialId(env, "cred-abc"))?.userId).toBe(userId)

    expect(await updateCredentialCounter(env, "cred-abc", 0, 5)).toBe(true)
    expect((await getCredentialByCredentialId(env, "cred-abc"))?.counter).toBe(5)
  })

  it("accepts only one concurrent counter advance from the same assertion", async () => {
    await insertCredential(env, {
      userId,
      credentialId: "cred-counter-race",
      publicKey: "cHVia2V5",
      counter: 7,
      transports: [],
      name: null,
    })

    const results = await Promise.all([
      updateCredentialCounter(env, "cred-counter-race", 7, 8),
      updateCredentialCounter(env, "cred-counter-race", 7, 8),
    ])

    expect(results.sort()).toEqual([false, true])
    expect((await getCredentialByCredentialId(env, "cred-counter-race"))?.counter).toBe(8)
  })

  it("preserves one login method when two passkeys are deleted concurrently", async () => {
    for (const credentialId of ["cred-delete-a", "cred-delete-b"]) {
      await insertCredential(env, {
        userId,
        credentialId,
        publicKey: "cHVia2V5",
        counter: 0,
        transports: [],
        name: credentialId,
      })
    }
    const credentials = await listCredentialSummaries(env, userId)
    const results = await Promise.all(
      credentials.map((credential) =>
        deleteCredentialPreservingLoginMethod(env, credential.id, userId),
      ),
    )

    expect(results.sort()).toEqual(["deleted", "last_login_method"])
    expect(await getCredentialsByUser(env, userId)).toHaveLength(1)
  })
})
