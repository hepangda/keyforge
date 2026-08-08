import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import {
  createSession,
  getSessionByToken,
  replaceReauthenticatedSession,
  revokeAllUserSessions,
  revokeOtherUserSessions,
  revokeSessionById,
  revokeSessionByToken,
} from "../../src/auth/session"
import { createUser } from "../../src/db/queries/users"
import { issueRefreshToken } from "../../src/tokens/refresh-token"

const cases = [
  {
    name: "token revocation",
    invoke: (_userId: string, target: { sessionId: string; token: string }, _keep: string) =>
      revokeSessionByToken(env, target.token),
  },
  {
    name: "all-user revocation",
    invoke: (userId: string, _target: { sessionId: string; token: string }, _keep: string) =>
      revokeAllUserSessions(env, userId),
  },
  {
    name: "single-session revocation",
    invoke: (userId: string, target: { sessionId: string; token: string }, _keep: string) =>
      revokeSessionById(env, target.sessionId, userId),
  },
  {
    name: "other-session revocation",
    invoke: (userId: string, _target: { sessionId: string; token: string }, keep: string) =>
      revokeOtherUserSessions(env, userId, keep),
  },
] as const

describe("atomic session and refresh-mirror revocation", () => {
  it.each(cases)("rolls back $name when the refresh mirror update fails", async ({
    name,
    invoke,
  }) => {
    const slug = name.replaceAll(/[^a-z]/g, "-")
    const user = await createUser(env, { email: `atomic-${slug}@pangda.app` })
    const keep = await createSession(env, {
      userId: user.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const target = await createSession(env, {
      userId: user.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const refresh = await issueRefreshToken(env, {
      userId: user.id,
      clientId: "pangda_app",
      sessionId: target.sessionId,
      resource: "https://api.pangda.app",
      scope: "openid offline_access",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })
    await env.DB.prepare(
      `CREATE TRIGGER fail_atomic_session_refresh
       BEFORE UPDATE OF revoked_at ON refresh_tokens
       BEGIN SELECT RAISE(ABORT, 'simulated refresh mirror failure'); END`,
    ).run()

    try {
      await expect(invoke(user.id, target, keep.sessionId)).rejects.toThrow()
    } finally {
      await env.DB.prepare("DROP TRIGGER IF EXISTS fail_atomic_session_refresh").run()
    }

    const sessionRows = await env.DB.prepare("SELECT revoked_at FROM sessions WHERE id IN (?, ?)")
      .bind(keep.sessionId, target.sessionId)
      .all<{ revoked_at: number | null }>()
    expect(sessionRows.results).toHaveLength(2)
    expect(sessionRows.results.every((row) => row.revoked_at === null)).toBe(true)
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

  it("reclaims a replacement session when revoking the previous session fails", async () => {
    const user = await createUser(env, { email: "atomic-reauth@pangda.app" })
    const previous = await createSession(env, {
      userId: user.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const next = await createSession(env, {
      userId: user.id,
      authMethod: "passkey",
      ttlSeconds: 3600,
    })
    const previousRecord = await getSessionByToken(env, previous.token)
    expect(previousRecord).not.toBeNull()
    if (previousRecord === null) return
    await env.DB.prepare(
      `CREATE TRIGGER fail_previous_reauthentication_revoke
       BEFORE UPDATE OF revoked_at ON sessions
       WHEN OLD.id = '${previous.sessionId}'
       BEGIN SELECT RAISE(ABORT, 'simulated previous session failure'); END`,
    ).run()
    try {
      await expect(
        replaceReauthenticatedSession(env, previousRecord, next, user.id),
      ).rejects.toThrow()
    } finally {
      await env.DB.prepare("DROP TRIGGER IF EXISTS fail_previous_reauthentication_revoke").run()
    }
    expect(await getSessionByToken(env, previous.token)).not.toBeNull()
    expect(await getSessionByToken(env, next.token)).toBeNull()
  })
})
