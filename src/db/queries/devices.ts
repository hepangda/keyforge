import { z } from "zod"
import type { DeviceStatus } from "../../types/domain"
import { DEVICE_STATUSES } from "../../types/domain"
import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"

export type DeviceSession = {
  readonly id: string
  readonly clientId: string
  readonly resourceUri: string | null
  readonly scope: string
  readonly status: DeviceStatus
  readonly userId: string | null
  readonly expiresAt: number
  readonly lastPolledAt: number | null
  readonly pollIntervalSeconds: number
  readonly sessionId: string | null
  readonly authTime: number | null
}

const deviceRowSchema = z.object({
  id: z.string(),
  client_id: z.string(),
  resource_uri: z.string().nullable(),
  scope: z.string(),
  status: z.enum(DEVICE_STATUSES),
  user_id: z.string().nullable(),
  expires_at: z.number(),
  last_polled_at: z.number().nullable(),
  poll_interval_seconds: z.number(),
  session_id: z.string().nullable(),
  auth_time: z.number().nullable(),
})

const DEVICE_COLUMNS =
  "id, client_id, resource_uri, scope, status, user_id, expires_at, last_polled_at, poll_interval_seconds, session_id, auth_time"

function mapDevice(row: unknown): DeviceSession {
  const parsed = deviceRowSchema.parse(row)
  return {
    id: parsed.id,
    clientId: parsed.client_id,
    resourceUri: parsed.resource_uri,
    scope: parsed.scope,
    status: parsed.status,
    userId: parsed.user_id,
    expiresAt: parsed.expires_at,
    lastPolledAt: parsed.last_polled_at,
    pollIntervalSeconds: parsed.poll_interval_seconds,
    sessionId: parsed.session_id,
    authTime: parsed.auth_time,
  }
}

export type CreateDeviceSessionInput = {
  readonly deviceCodeHash: string
  readonly userCodeHash: string
  readonly clientId: string
  readonly resourceUri: string | null
  readonly scope: string
  readonly expiresAt: number
  readonly pollIntervalSeconds: number
  readonly maxActiveSessions: number
}

export async function createDeviceSession(
  env: Env,
  input: CreateDeviceSessionInput,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `INSERT INTO device_authorization_sessions
       (id, device_code_hash, user_code_hash, client_id, resource_uri, scope, status,
        poll_interval_seconds, poll_count, expires_at, created_at)
     SELECT ?, ?, ?, ?, ?, ?, 'pending', ?, 0, ?, ?
     WHERE (
       SELECT COUNT(*) FROM device_authorization_sessions
       WHERE client_id = ? AND status IN ('pending', 'approved') AND expires_at > ?
     ) < ?`,
  )
    .bind(
      generateId(ID_PREFIX.device),
      input.deviceCodeHash,
      input.userCodeHash,
      input.clientId,
      input.resourceUri,
      input.scope,
      input.pollIntervalSeconds,
      input.expiresAt,
      nowSeconds(),
      input.clientId,
      nowSeconds(),
      input.maxActiveSessions,
    )
    .run()
  return result.meta.changes === 1
}

export async function getDeviceByUserCodeHash(
  env: Env,
  hash: string,
): Promise<DeviceSession | null> {
  const row = await env.DB.prepare(
    `SELECT ${DEVICE_COLUMNS} FROM device_authorization_sessions WHERE user_code_hash = ?`,
  )
    .bind(hash)
    .first()
  return row === null ? null : mapDevice(row)
}

export async function getDeviceByDeviceCodeHash(
  env: Env,
  hash: string,
): Promise<DeviceSession | null> {
  const row = await env.DB.prepare(
    `SELECT ${DEVICE_COLUMNS} FROM device_authorization_sessions WHERE device_code_hash = ?`,
  )
    .bind(hash)
    .first()
  return row === null ? null : mapDevice(row)
}

export async function approveDevice(
  env: Env,
  id: string,
  userId: string,
  sessionId: string,
  authTime: number,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE device_authorization_sessions
     SET status = 'approved', user_id = ?, session_id = ?, auth_time = ?, approved_at = ?
     WHERE id = ? AND status = 'pending'`,
  )
    .bind(userId, sessionId, authTime, nowSeconds(), id)
    .run()
  return result.meta.changes === 1
}

/** Approve and persist the represented consent in one D1 transaction. */
export async function approveDeviceWithConsent(
  env: Env,
  input: {
    readonly id: string
    readonly userId: string
    readonly sessionId: string
    readonly authTime: number
    readonly clientId: string
    readonly scope: string
    readonly resource: string
  },
): Promise<boolean> {
  const now = nowSeconds()
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO consents (id, user_id, client_id, scope, resource, created_at, updated_at)
       SELECT ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (
         SELECT 1 FROM device_authorization_sessions WHERE id = ? AND status = 'pending'
       )
       ON CONFLICT(user_id, client_id, resource)
         DO UPDATE SET
           scope = (
             SELECT group_concat(value, ' ')
             FROM (
               SELECT value, MIN(source) AS source, MIN(position) AS position
               FROM (
                 SELECT value, 0 AS source, key AS position
                 FROM json_each('["' || replace(consents.scope, ' ', '","') || '"]')
                 UNION ALL
                 SELECT value, 1 AS source, key AS position
                 FROM json_each('["' || replace(excluded.scope, ' ', '","') || '"]')
               )
               GROUP BY value
               ORDER BY source, position
             )
           ),
           updated_at = excluded.updated_at`,
    ).bind(
      generateId(ID_PREFIX.consent),
      input.userId,
      input.clientId,
      input.scope,
      input.resource,
      now,
      now,
      input.id,
    ),
    env.DB.prepare(
      `UPDATE device_authorization_sessions
       SET status = 'approved', user_id = ?, session_id = ?, auth_time = ?, approved_at = ?
       WHERE id = ? AND status = 'pending'`,
    ).bind(input.userId, input.sessionId, input.authTime, now, input.id),
  ])
  return results[1]?.meta.changes === 1
}

export async function denyDevice(env: Env, id: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE device_authorization_sessions SET status = 'denied', denied_at = ? WHERE id = ? AND status = 'pending'",
  )
    .bind(nowSeconds(), id)
    .run()
  return result.meta.changes === 1
}

/** Atomically consume an approved session exactly once (returns false on a race). */
export async function consumeApprovedDevice(env: Env, id: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE device_authorization_sessions SET status = 'consumed' WHERE id = ? AND status = 'approved'",
  )
    .bind(id)
    .run()
  return result.meta.changes === 1
}

export async function markDeviceExpired(env: Env, id: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE device_authorization_sessions SET status = 'expired' WHERE id = ? AND status IN ('pending', 'approved')",
  )
    .bind(id)
    .run()
}

export async function recordDevicePoll(env: Env, id: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE device_authorization_sessions SET last_polled_at = ?, poll_count = poll_count + 1 WHERE id = ?",
  )
    .bind(nowSeconds(), id)
    .run()
}

/** RFC 8628 slow_down: count the poll and increase every later interval by 5s. */
export async function recordDeviceSlowPoll(env: Env, id: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE device_authorization_sessions
     SET last_polled_at = ?, poll_count = poll_count + 1, poll_interval_seconds = poll_interval_seconds + 5
     WHERE id = ?`,
  )
    .bind(nowSeconds(), id)
    .run()
}
