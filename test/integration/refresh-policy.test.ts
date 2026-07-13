import { env, runInDurableObject, SELF } from "cloudflare:test"
import { createLocalJWKSet, jwtVerify } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { REFRESH_TOKEN_POLICY } from "../../src/config"
import { saveConsent } from "../../src/db/queries/consents"
import { createUser } from "../../src/db/queries/users"
import type { RefreshFamilyMeta, RotateResult } from "../../src/do/RefreshTokenFamilyDO"
import { getPublicJwks } from "../../src/tokens/key-rotation"
import { issueRefreshToken } from "../../src/tokens/refresh-token"
import { hashOpaqueToken } from "../../src/tokens/token-hash"

const ISSUER = "https://auth.pangda.app"
const CLIENT = "pangda_app"
const OTHER_CLIENT = "pangda_admin"
const RESOURCE = "https://api.pangda.app"
const SCOPE = "openid profile email offline_access api.read"
const AUTH_TIME = 1_700_000_000
const CLIENT_SCOPES = JSON.stringify([
  "openid",
  "profile",
  "email",
  "groups",
  "offline_access",
  "app.read",
  "api.read",
  "api.write",
])
const RESOURCE_SCOPES = JSON.stringify([
  "openid",
  "profile",
  "email",
  "groups",
  "offline_access",
  "api.read",
  "api.write",
])

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM authorization_grants"),
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM consents"),
    env.DB.prepare("DELETE FROM users"),
    env.DB.prepare(
      `UPDATE oauth_clients
       SET allowed_scopes_json = ?,
           allowed_grant_types_json = '["authorization_code","refresh_token"]',
           allowed_resources_json = '["https://app.pangda.app","https://api.pangda.app"]',
           enabled = 1
       WHERE client_id = ?`,
    ).bind(CLIENT_SCOPES, CLIENT),
    env.DB.prepare(
      "UPDATE oauth_resources SET allowed_scopes_json = ?, enabled = 1 WHERE resource_uri = ?",
    ).bind(RESOURCE_SCOPES, RESOURCE),
  ])
})

async function seedRefreshFamily() {
  const user = await createUser(env, {
    email: "refresh-policy@pangda.app",
    name: "Refresh Policy",
    userType: "internal",
    emailVerified: true,
  })
  const session = await createSession(env, {
    userId: user.id,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  await saveConsent(env, {
    userId: user.id,
    clientId: CLIENT,
    scope: SCOPE,
    resource: RESOURCE,
  })
  const refresh = await issueRefreshToken(env, {
    userId: user.id,
    clientId: CLIENT,
    sessionId: session.sessionId,
    resource: RESOURCE,
    scope: SCOPE,
    authTime: AUTH_TIME,
    rememberMe: false,
  })
  return { user, session, refresh }
}

function refreshRequest(refreshToken: string, clientId = CLIENT): Promise<Response> {
  return SELF.fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
    }).toString(),
  })
}

async function expectGeneration(familyId: string, generation: number): Promise<void> {
  const state = await env.REFRESH_TOKEN_FAMILY.getByName(familyId).getState()
  expect(state?.generation).toBe(generation)
  expect(state?.revoked).toBe(false)
}

async function expectInvalidGrant(response: Response): Promise<void> {
  expect(response.status).toBe(400)
  expect((await response.json<{ error: string }>()).error).toBe("invalid_grant")
}

describe("refresh token client boundary", () => {
  it("rejects the wrong client before rotation and leaves the family usable", async () => {
    const { refresh } = await seedRefreshFamily()

    await expectInvalidGrant(await refreshRequest(refresh.token, OTHER_CLIENT))
    await expectGeneration(refresh.familyId, 0)

    expect((await refreshRequest(refresh.token)).status).toBe(200)
    await expectGeneration(refresh.familyId, 1)
  })
})

describe("refresh token current-policy enforcement", () => {
  it("rejects a disabled user without consuming the refresh token", async () => {
    const { user, refresh } = await seedRefreshFamily()
    await env.DB.prepare("UPDATE users SET disabled = 1 WHERE id = ?").bind(user.id).run()

    await expectInvalidGrant(await refreshRequest(refresh.token))
    await expectGeneration(refresh.familyId, 0)

    await env.DB.prepare("UPDATE users SET disabled = 0 WHERE id = ?").bind(user.id).run()
    expect((await refreshRequest(refresh.token)).status).toBe(200)
  })

  it("rejects scopes removed from the client's current policy", async () => {
    const { refresh } = await seedRefreshFamily()
    await env.DB.prepare(
      `UPDATE oauth_clients
       SET allowed_scopes_json = '["openid","profile","email","groups","offline_access"]'
       WHERE client_id = ?`,
    )
      .bind(CLIENT)
      .run()

    await expectInvalidGrant(await refreshRequest(refresh.token))
    await expectGeneration(refresh.familyId, 0)

    await env.DB.prepare("UPDATE oauth_clients SET allowed_scopes_json = ? WHERE client_id = ?")
      .bind(CLIENT_SCOPES, CLIENT)
      .run()
    expect((await refreshRequest(refresh.token)).status).toBe(200)
  })

  it("rejects a disabled resource without consuming the refresh token", async () => {
    const { refresh } = await seedRefreshFamily()
    await env.DB.prepare("UPDATE oauth_resources SET enabled = 0 WHERE resource_uri = ?")
      .bind(RESOURCE)
      .run()

    await expectInvalidGrant(await refreshRequest(refresh.token))
    await expectGeneration(refresh.familyId, 0)

    await env.DB.prepare("UPDATE oauth_resources SET enabled = 1 WHERE resource_uri = ?")
      .bind(RESOURCE)
      .run()
    expect((await refreshRequest(refresh.token)).status).toBe(200)
  })

  it("rejects scopes removed from the resource's current policy", async () => {
    const { refresh } = await seedRefreshFamily()
    await env.DB.prepare(
      `UPDATE oauth_resources
       SET allowed_scopes_json = '["openid","profile","email","groups","offline_access"]'
       WHERE resource_uri = ?`,
    )
      .bind(RESOURCE)
      .run()

    await expectInvalidGrant(await refreshRequest(refresh.token))
    await expectGeneration(refresh.familyId, 0)

    await env.DB.prepare(
      "UPDATE oauth_resources SET allowed_scopes_json = ? WHERE resource_uri = ?",
    )
      .bind(RESOURCE_SCOPES, RESOURCE)
      .run()
    expect((await refreshRequest(refresh.token)).status).toBe(200)
  })
})

describe("refresh ID token authentication time", () => {
  it("preserves the original auth_time instead of treating refresh as a new login", async () => {
    const { refresh } = await seedRefreshFamily()
    const response = await refreshRequest(refresh.token)
    expect(response.status).toBe(200)
    const body = await response.json<{ id_token: string }>()

    const jwks = createLocalJWKSet({ keys: [...(await getPublicJwks(env)).keys] })
    const { payload } = await jwtVerify(body.id_token, jwks, {
      issuer: ISSUER,
      audience: CLIENT,
    })
    expect(payload["auth_time"]).toBe(AUTH_TIME)
  })
})

describe("refresh family safety bounds", () => {
  it("rate-limits hot sequential rotation without consuming the current token", async () => {
    const { refresh } = await seedRefreshFamily()
    const first = await refreshRequest(refresh.token)
    expect(first.status).toBe(200)
    const current = (await first.json<{ refresh_token: string }>()).refresh_token

    const tooSoon = await refreshRequest(current)
    expect(tooSoon.status).toBe(429)
    expect(await tooSoon.json()).toMatchObject({ error: "temporarily_unavailable" })
    const retryAfter = Number(tooSoon.headers.get("retry-after"))
    expect(retryAfter).toBeGreaterThan(0)
    expect(retryAfter).toBeLessThanOrEqual(REFRESH_TOKEN_POLICY.minimumRotationIntervalSeconds)
    await expectGeneration(refresh.familyId, 1)

    const stub = env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId)
    await runInDurableObject(stub, async (_instance, state) => {
      const meta = await state.storage.get<RefreshFamilyMeta>("meta")
      expect(meta).toBeDefined()
      if (meta !== undefined) {
        await state.storage.put("meta", {
          ...meta,
          lastRotatedAt: meta.lastRotatedAt - REFRESH_TOKEN_POLICY.minimumRotationIntervalSeconds,
        })
      }
    })

    expect((await refreshRequest(current)).status).toBe(200)
    await expectGeneration(refresh.familyId, 2)
  })

  it("serializes concurrent rotation and preserves replay-family burning", async () => {
    const { refresh } = await seedRefreshFamily()
    const stub = env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId)
    const presentedHash = await hashOpaqueToken(refresh.token)
    const [left, right] = await Promise.all([
      stub.rotate(presentedHash, await hashOpaqueToken("next-left"), CLIENT, SCOPE),
      stub.rotate(presentedHash, await hashOpaqueToken("next-right"), CLIENT, SCOPE),
    ])
    const statuses = [left.status, right.status].sort()
    expect(statuses).toEqual(["reuse_detected", "rotated"] satisfies RotateResult["status"][])
    expect((await stub.getState())?.revoked).toBe(true)
  })

  it("revokes a family at the generation ceiling and requires reauthorization", async () => {
    const { refresh } = await seedRefreshFamily()
    const stub = env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId)
    await runInDurableObject(stub, async (_instance, state) => {
      const meta = await state.storage.get<RefreshFamilyMeta>("meta")
      expect(meta).toBeDefined()
      if (meta !== undefined) {
        await state.storage.put("meta", {
          ...meta,
          generation: REFRESH_TOKEN_POLICY.maximumGeneration - 1,
          lastRotatedAt: meta.lastRotatedAt - REFRESH_TOKEN_POLICY.minimumRotationIntervalSeconds,
        })
      }
    })
    await env.DB.prepare(
      "UPDATE refresh_tokens SET generation = ?, last_rotated_at = 0 WHERE id = ?",
    )
      .bind(REFRESH_TOKEN_POLICY.maximumGeneration - 1, refresh.familyId)
      .run()

    const finalRotation = await refreshRequest(refresh.token)
    expect(finalRotation.status).toBe(200)
    const finalToken = (await finalRotation.json<{ refresh_token: string }>()).refresh_token
    expect((await stub.getState())?.generation).toBe(REFRESH_TOKEN_POLICY.maximumGeneration)

    const exhausted = await refreshRequest(finalToken)
    await expectInvalidGrant(exhausted)
    expect((await stub.getState())?.revoked).toBe(true)
    const mirror = await env.DB.prepare(
      "SELECT generation, revoked_at FROM refresh_tokens WHERE id = ?",
    )
      .bind(refresh.familyId)
      .first<{ generation: number; revoked_at: number | null }>()
    expect(mirror?.generation).toBe(REFRESH_TOKEN_POLICY.maximumGeneration)
    expect(mirror?.revoked_at).not.toBeNull()
  })

  it("keeps concurrent issuance within the user/client cap and revokes the oldest DO", async () => {
    const { user, session, refresh: oldest } = await seedRefreshFamily()
    await env.DB.prepare("UPDATE refresh_tokens SET created_at = 1 WHERE id = ?")
      .bind(oldest.familyId)
      .run()
    const issueAnother = () =>
      issueRefreshToken(env, {
        userId: user.id,
        clientId: CLIENT,
        sessionId: session.sessionId,
        resource: RESOURCE,
        scope: SCOPE,
        authTime: AUTH_TIME,
        rememberMe: false,
      })

    for (
      let index = 1;
      index < REFRESH_TOKEN_POLICY.maximumActiveFamiliesPerUserClient - 1;
      index += 1
    ) {
      const issued = await issueAnother()
      await env.DB.prepare("UPDATE refresh_tokens SET created_at = ? WHERE id = ?")
        .bind(index + 1, issued.familyId)
        .run()
    }

    const otherClient = await issueRefreshToken(env, {
      userId: user.id,
      clientId: OTHER_CLIENT,
      sessionId: session.sessionId,
      resource: RESOURCE,
      scope: SCOPE,
      authTime: AUTH_TIME,
      rememberMe: false,
    })
    const newest = await Promise.all([issueAnother(), issueAnother()])

    const active = await env.DB.prepare(
      `SELECT id FROM refresh_tokens
       WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL AND expires_at > ?
       ORDER BY created_at ASC, id ASC`,
    )
      .bind(user.id, CLIENT, Math.floor(Date.now() / 1000))
      .all<{ id: string }>()
    expect(active.results).toHaveLength(REFRESH_TOKEN_POLICY.maximumActiveFamiliesPerUserClient)
    expect(active.results.map((row) => row.id)).toEqual(
      expect.arrayContaining(newest.map((family) => family.familyId)),
    )

    const oldestMirror = await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
      .bind(oldest.familyId)
      .first<{ revoked_at: number | null }>()
    expect(oldestMirror?.revoked_at).not.toBeNull()
    expect((await env.REFRESH_TOKEN_FAMILY.getByName(oldest.familyId).getState())?.revoked).toBe(
      true,
    )
    const otherMirror = await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
      .bind(otherClient.familyId)
      .first<{ revoked_at: number | null }>()
    expect(otherMirror?.revoked_at).toBeNull()
    expect(
      (await env.REFRESH_TOKEN_FAMILY.getByName(otherClient.familyId).getState())?.revoked,
    ).toBe(false)
  })
})
