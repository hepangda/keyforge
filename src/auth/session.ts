import * as z from "zod"
import { AppError } from "../security/errors"
import { revokeRefreshFamilyDurableObjects } from "../tokens/refresh-token-revocation"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AuthMethod, SessionId, SessionRecord } from "../types/domain"
import { AUTH_METHODS, asSessionId, asUserId } from "../types/domain"
import { generateId, ID_PREFIX } from "../utils/id"
import { randomToken } from "../utils/random"
import { nowSeconds } from "../utils/time"

export type CreateSessionInput = {
  readonly userId: string
  readonly authMethod: AuthMethod
  readonly ttlSeconds: number
  readonly passkeyAuthenticated?: boolean
  readonly ipHash?: string | null
  readonly userAgentHash?: string | null
}

export type CreatedSession = {
  readonly sessionId: string
  readonly token: string
  readonly expiresAt: number
}

export async function createSession(env: Env, input: CreateSessionInput): Promise<CreatedSession> {
  const sessionId = generateId(ID_PREFIX.session)
  const token = randomToken(32)
  const now = nowSeconds()
  const expiresAt = now + input.ttlSeconds
  const inserted = await env.DB.prepare(
    `INSERT INTO sessions
       (id, user_id, token_hash, auth_method, auth_time, passkey_authenticated, amr_json,
        ip_hash, user_agent_hash, created_at, last_seen_at, expires_at)
     SELECT ?, id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
     FROM users WHERE id = ? AND disabled = 0`,
  )
    .bind(
      sessionId,
      await hashOpaqueToken(token),
      input.authMethod,
      now,
      input.passkeyAuthenticated === true ? 1 : 0,
      JSON.stringify([input.authMethod]),
      input.ipHash ?? null,
      input.userAgentHash ?? null,
      now,
      now,
      expiresAt,
      input.userId,
    )
    .run()
  if (inserted.meta.changes !== 1) {
    throw new AppError(403, "This account is unavailable")
  }
  return { sessionId, token, expiresAt }
}

/** Create a session only while a one-time capability's security epoch is current. */
export async function createSessionAtSecurityVersion(
  env: Env,
  input: CreateSessionInput,
  expectedSecurityVersion: number,
): Promise<CreatedSession | null> {
  const sessionId = generateId(ID_PREFIX.session)
  const token = randomToken(32)
  const now = nowSeconds()
  const expiresAt = now + input.ttlSeconds
  const result = await env.DB.prepare(
    `INSERT INTO sessions
       (id, user_id, token_hash, auth_method, auth_time, passkey_authenticated, amr_json,
        ip_hash, user_agent_hash, created_at, last_seen_at, expires_at)
     SELECT ?, id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
     FROM users
     WHERE id = ? AND disabled = 0 AND security_version = ?`,
  )
    .bind(
      sessionId,
      await hashOpaqueToken(token),
      input.authMethod,
      now,
      input.passkeyAuthenticated === true ? 1 : 0,
      JSON.stringify([input.authMethod]),
      input.ipHash ?? null,
      input.userAgentHash ?? null,
      now,
      now,
      expiresAt,
      input.userId,
      expectedSecurityVersion,
    )
    .run()
  return result.meta.changes === 1 ? { sessionId, token, expiresAt } : null
}

const sessionRowSchema = z.object({
  id: z.string(),
  user_id: z.string(),
  auth_method: z.enum(AUTH_METHODS),
  auth_time: z.number(),
  passkey_authenticated: z.number(),
  created_at: z.number(),
  last_seen_at: z.number(),
  expires_at: z.number(),
  revoked_at: z.number().nullable(),
})

export async function getSessionByToken(env: Env, token: string): Promise<SessionRecord | null> {
  const row = await env.DB.prepare(
    `SELECT id, user_id, auth_method, auth_time, passkey_authenticated, created_at, last_seen_at, expires_at, revoked_at
     FROM sessions WHERE token_hash = ?`,
  )
    .bind(await hashOpaqueToken(token))
    .first()
  if (row === null) {
    return null
  }
  const parsed = sessionRowSchema.parse(row)
  if (parsed.revoked_at !== null || nowSeconds() >= parsed.expires_at) {
    return null
  }
  return {
    id: asSessionId(parsed.id),
    userId: asUserId(parsed.user_id),
    authMethod: parsed.auth_method,
    authTime: parsed.auth_time,
    passkeyAuthenticated: parsed.passkey_authenticated === 1,
    createdAt: parsed.created_at,
    lastSeenAt: parsed.last_seen_at,
    expiresAt: parsed.expires_at,
  }
}

/** Load a live session by id for authorization-code validity checks. */
export async function getSessionById(env: Env, sessionId: string): Promise<SessionRecord | null> {
  const row = await env.DB.prepare(
    `SELECT id, user_id, auth_method, auth_time, passkey_authenticated, created_at, last_seen_at, expires_at, revoked_at
     FROM sessions WHERE id = ?`,
  )
    .bind(sessionId)
    .first()
  if (row === null) return null
  const parsed = sessionRowSchema.parse(row)
  if (parsed.revoked_at !== null || nowSeconds() >= parsed.expires_at) return null
  return {
    id: asSessionId(parsed.id),
    userId: asUserId(parsed.user_id),
    authMethod: parsed.auth_method,
    authTime: parsed.auth_time,
    passkeyAuthenticated: parsed.passkey_authenticated === 1,
    createdAt: parsed.created_at,
    lastSeenAt: parsed.last_seen_at,
    expiresAt: parsed.expires_at,
  }
}

export async function touchSession(env: Env, sessionId: string, seenAt: number): Promise<void> {
  await env.DB.prepare(
    `UPDATE sessions SET last_seen_at = ?
     WHERE id = ? AND revoked_at IS NULL AND last_seen_at < ?`,
  )
    .bind(seenAt, sessionId, seenAt)
    .run()
}

export async function revokeSessionByToken(env: Env, token: string): Promise<void> {
  const now = nowSeconds()
  const tokenHash = await hashOpaqueToken(token)
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE token_hash = ? AND revoked_at IS NULL`,
    ).bind(now, tokenHash),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE session_id IN (SELECT id FROM sessions WHERE token_hash = ?)
         AND revoked_at IS NULL
       RETURNING id`,
    ).bind(now, tokenHash),
  ])
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds(results[1]))
}

export async function revokeAllUserSessions(env: Env, userId: string): Promise<void> {
  const now = nowSeconds()
  const results = await env.DB.batch([
    env.DB.prepare(
      "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
    ).bind(now, userId),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
       RETURNING id`,
    ).bind(now, userId),
  ])
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds(results[1]))
}

export type SessionSummary = {
  readonly id: SessionId
  readonly authMethod: AuthMethod
  readonly passkeyAuthenticated: boolean
  readonly createdAt: number
  readonly lastSeenAt: number
  readonly expiresAt: number
}

const sessionSummaryRowSchema = z.object({
  id: z.string(),
  auth_method: z.enum(AUTH_METHODS),
  passkey_authenticated: z.number(),
  created_at: z.number(),
  last_seen_at: z.number(),
  expires_at: z.number(),
})

export async function listSessionsByUser(env: Env, userId: string): Promise<SessionSummary[]> {
  const result = await env.DB.prepare(
    `SELECT id, auth_method, passkey_authenticated, created_at, last_seen_at, expires_at
     FROM sessions
     WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
     ORDER BY last_seen_at DESC`,
  )
    .bind(userId, nowSeconds())
    .all()
  return result.results.map((row) => {
    const parsed = sessionSummaryRowSchema.parse(row)
    return {
      id: asSessionId(parsed.id),
      authMethod: parsed.auth_method,
      passkeyAuthenticated: parsed.passkey_authenticated === 1,
      createdAt: parsed.created_at,
      lastSeenAt: parsed.last_seen_at,
      expiresAt: parsed.expires_at,
    }
  })
}

export async function revokeSessionById(
  env: Env,
  sessionId: string,
  userId: string,
): Promise<boolean> {
  const now = nowSeconds()
  const results = await env.DB.batch([
    env.DB.prepare(
      "UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    ).bind(now, sessionId, userId),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE session_id = ? AND revoked_at IS NULL
         AND EXISTS (SELECT 1 FROM sessions WHERE id = ? AND user_id = ?)
       RETURNING id`,
    ).bind(now, sessionId, sessionId, userId),
  ])
  const revoked = results[0]?.meta.changes === 1
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds(results[1]))
  return revoked
}
export async function replaceReauthenticatedSession(
  env: Env,
  previous: SessionRecord | undefined,
  next: CreatedSession,
  nextUserId: string,
): Promise<void> {
  if (previous === undefined) return
  try {
    await revokeSessionById(env, previous.id, previous.userId)
  } catch (error) {
    try {
      await revokeSessionById(env, next.sessionId, nextUserId)
    } catch (cleanupError) {
      console.error("session.reauthentication_cleanup_failed", next.sessionId, cleanupError)
    }
    throw error
  }
}

export async function revokeOtherUserSessions(
  env: Env,
  userId: string,
  keepSessionId: string,
): Promise<number> {
  const now = nowSeconds()
  const results = await env.DB.batch([
    env.DB.prepare(
      "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL",
    ).bind(now, userId, keepSessionId),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND (session_id IS NULL OR session_id != ?) AND revoked_at IS NULL
       RETURNING id`,
    ).bind(now, userId, keepSessionId),
  ])
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds(results[1]))
  return results[0]?.meta.changes ?? 0
}

function refreshFamilyIds(result: D1Result<unknown> | undefined): string[] {
  return z
    .array(z.object({ id: z.string() }))
    .parse(result?.results ?? [])
    .map((row) => row.id)
}
