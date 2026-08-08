import { env, SELF } from "cloudflare:test"
import { decodeJwt } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { DEVICE_CODE_GRANT } from "../../src/config"
import { createUser } from "../../src/db/queries/users"
import { hashOpaqueToken } from "../../src/tokens/token-hash"

const ISSUER = "https://auth.pangda.app"
const CLI = "pangda_cli"
const SCOPE = "openid profile email offline_access api.read"
const RESOURCE = "https://api.pangda.app"

let sessionToken = ""
let userId = ""

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM device_authorization_sessions"),
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM users"),
  ])
  await env.DB.prepare(
    `UPDATE oauth_resources
     SET allowed_scopes_json = '["openid","profile","email","offline_access","api.read","api.write"]'
     WHERE resource_uri = ?`,
  )
    .bind(RESOURCE)
    .run()
  const user = await createUser(env, {
    email: "cli@pangda.app",
    name: "CLI User",
  })
  userId = user.id
  await env.DB.prepare(
    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_employees', unixepoch())",
  )
    .bind(user.id)
    .run()
  const session = await createSession(env, {
    userId: user.id,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  sessionToken = session.token
})

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

async function startDevice(): Promise<{ deviceCode: string; userCode: string; interval: number }> {
  const res = await SELF.fetch(`${ISSUER}/oauth/device_authorization`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLI, scope: SCOPE, resource: RESOURCE }).toString(),
  })
  expect(res.status).toBe(200)
  const body = await res.json<{ device_code: string; user_code: string; interval: number }>()
  return { deviceCode: body.device_code, userCode: body.user_code, interval: body.interval }
}

function poll(deviceCode: string): Promise<Response> {
  return SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: DEVICE_CODE_GRANT,
      device_code: deviceCode,
      client_id: CLI,
    }).toString(),
  })
}

async function resetPollTimer(deviceCode: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE device_authorization_sessions SET last_polled_at = NULL WHERE device_code_hash = ?",
  )
    .bind(await hashOpaqueToken(deviceCode))
    .run()
}

async function decide(userCode: string, decision: "approve" | "deny"): Promise<void> {
  const getRes = await SELF.fetch(`${ISSUER}/device?user_code=${encodeURIComponent(userCode)}`, {
    headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
  })
  const csrf = cookieValue(getRes.headers.getSetCookie(), "__Host-keyforge_csrf")
  const res = await SELF.fetch(`${ISSUER}/device/confirm`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_session=${sessionToken}; __Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ user_code: userCode, decision, csrf_token: csrf }).toString(),
  })
  expect(res.status).toBe(200)
}

describe("device authorization grant", () => {
  it("starts a device flow with a user_code and interval", async () => {
    const { deviceCode, userCode, interval } = await startDevice()
    expect(deviceCode).toBeTruthy()
    expect(userCode).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
    expect(interval).toBe(5)
  })

  it("rejects a scope allowed by the client but not by the resource", async () => {
    await env.DB.prepare(
      "UPDATE oauth_resources SET allowed_scopes_json = '[\"api.write\"]' WHERE resource_uri = ?",
    )
      .bind(RESOURCE)
      .run()
    const res = await SELF.fetch(`${ISSUER}/oauth/device_authorization`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLI,
        scope: "api.read",
        resource: RESOURCE,
      }).toString(),
    })
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("invalid_scope")
  })

  it("returns authorization_pending before approval", async () => {
    const { deviceCode } = await startDevice()
    const res = await poll(deviceCode)
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("authorization_pending")
  })

  it("returns slow_down when polled faster than the interval", async () => {
    const { deviceCode } = await startDevice()
    await poll(deviceCode)
    const res = await poll(deviceCode)
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("slow_down")
  })

  it("issues tokens after approval and consumes the code once", async () => {
    const { deviceCode, userCode } = await startDevice()
    await decide(userCode, "approve")
    await resetPollTimer(deviceCode)

    const res = await poll(deviceCode)
    expect(res.status).toBe(200)
    const body = await res.json<{ access_token: string; id_token: string; refresh_token: string }>()
    expect(body.access_token).toBeTruthy()
    expect(body.id_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
    expect(decodeJwt(body.id_token)).not.toHaveProperty("groups")
    expect(decodeJwt(body.access_token)).not.toHaveProperty("groups")

    await resetPollTimer(deviceCode)
    const second = await poll(deviceCode)
    expect(second.status).toBe(400)
    expect((await second.json<{ error: string }>()).error).toBe("invalid_grant")
  })

  it("does not consume an approved code when current membership denies access", async () => {
    const { deviceCode, userCode } = await startDevice()
    await decide(userCode, "approve")
    await env.DB.prepare("DELETE FROM user_groups WHERE user_id = ?").bind(userId).run()
    await resetPollTimer(deviceCode)

    const denied = await poll(deviceCode)
    expect(denied.status).toBe(400)
    expect((await denied.json<{ error: string }>()).error).toBe("invalid_grant")
    const pending = await env.DB.prepare(
      "SELECT status FROM device_authorization_sessions WHERE device_code_hash = ?",
    )
      .bind(await hashOpaqueToken(deviceCode))
      .first<{ status: string }>()
    expect(pending?.status).toBe("approved")

    await env.DB.prepare(
      "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_employees', unixepoch())",
    )
      .bind(userId)
      .run()
    await resetPollTimer(deviceCode)
    expect((await poll(deviceCode)).status).toBe(200)
  })
  it("returns access_denied after the user denies", async () => {
    const { deviceCode, userCode } = await startDevice()
    await decide(userCode, "deny")
    await resetPollTimer(deviceCode)
    const res = await poll(deviceCode)
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("access_denied")
  })

  it("returns expired_token for an expired device code", async () => {
    const { deviceCode } = await startDevice()
    await env.DB.prepare(
      "UPDATE device_authorization_sessions SET expires_at = 1 WHERE device_code_hash = ?",
    )
      .bind(await hashOpaqueToken(deviceCode))
      .run()
    const res = await poll(deviceCode)
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("expired_token")
  })

  it("preserves normalized codes for missing GET and POST sessions", async () => {
    const getResponse = await SELF.fetch(`${ISSUER}/device?user_code=abcd-efgh`, {
      redirect: "manual",
    })
    expect(getResponse.status).toBe(302)
    const getLogin = new URL(getResponse.headers.get("location") ?? "", ISSUER)
    expect(getLogin.pathname).toBe("/login")
    expect(getLogin.searchParams.has("reauth")).toBe(false)
    expect(getLogin.searchParams.get("return_to")).toBe("/device?user_code=ABCDEFGH")

    const postResponse = await SELF.fetch(`${ISSUER}/device/confirm`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ user_code: "abcd efgh", decision: "approve" }).toString(),
      redirect: "manual",
    })
    expect(postResponse.status).toBe(302)
    const postLogin = new URL(postResponse.headers.get("location") ?? "", ISSUER)
    expect(postLogin.searchParams.has("reauth")).toBe(false)
    expect(postLogin.searchParams.get("return_to")).toBe("/device?user_code=ABCDEFGH")
  })

  it("uses reauthentication for stale GET and POST sessions without looping", async () => {
    await env.DB.prepare("UPDATE sessions SET auth_time = 0 WHERE revoked_at IS NULL").run()
    for (const request of [
      SELF.fetch(`${ISSUER}/device?user_code=abcd-efgh`, {
        headers: { cookie: `__Host-keyforge_session=${sessionToken}` },
        redirect: "manual",
      }),
      SELF.fetch(`${ISSUER}/device/confirm`, {
        method: "POST",
        headers: {
          cookie: `__Host-keyforge_session=${sessionToken}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ user_code: "abcd-efgh", decision: "approve" }).toString(),
        redirect: "manual",
      }),
    ]) {
      const response = await request
      expect(response.status).toBe(302)
      const login = new URL(response.headers.get("location") ?? "", ISSUER)
      expect(login.pathname).toBe("/login")
      expect(login.searchParams.get("reauth")).toBe("1")
      expect(login.searchParams.get("hint")).toBe("authorize_device")
      expect(login.searchParams.get("return_to")).toBe("/device?user_code=ABCDEFGH")
    }
  })

  it("retains the normalized code after a CSRF error", async () => {
    const response = await SELF.fetch(`${ISSUER}/device/confirm`, {
      method: "POST",
      headers: {
        cookie: `__Host-keyforge_session=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ user_code: "abcd-efgh", decision: "approve" }).toString(),
    })
    expect(response.status).toBe(403)
    const html = await response.text()
    expect(html).toContain('name="user_code" required')
    expect(html).toContain('value="ABCDEFGH"')
  })
})
