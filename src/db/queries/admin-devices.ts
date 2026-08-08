import * as z from "zod"
import type { DeviceStatus } from "../../types/domain"
import { DEVICE_STATUSES } from "../../types/domain"
import { nowSeconds } from "../../utils/time"

export type AdminDeviceSession = {
  readonly id: string
  readonly clientId: string
  readonly resourceUri: string | null
  readonly scope: string
  readonly status: DeviceStatus
  readonly userId: string | null
  readonly expiresAt: number
  readonly approvedAt: number | null
  readonly deniedAt: number | null
  readonly lastPolledAt: number | null
  readonly pollCount: number
  readonly createdAt: number
}

const rowSchema = z.object({
  id: z.string(),
  client_id: z.string(),
  resource_uri: z.string().nullable(),
  scope: z.string(),
  status: z.enum(DEVICE_STATUSES),
  user_id: z.string().nullable(),
  expires_at: z.number(),
  approved_at: z.number().nullable(),
  denied_at: z.number().nullable(),
  last_polled_at: z.number().nullable(),
  poll_count: z.number(),
  created_at: z.number(),
})

const COLUMNS =
  "id, client_id, resource_uri, scope, status, user_id, expires_at, approved_at, denied_at, last_polled_at, poll_count, created_at"

function mapRow(row: unknown): AdminDeviceSession {
  const parsed = rowSchema.parse(row)
  return {
    id: parsed.id,
    clientId: parsed.client_id,
    resourceUri: parsed.resource_uri,
    scope: parsed.scope,
    status: parsed.status,
    userId: parsed.user_id,
    expiresAt: parsed.expires_at,
    approvedAt: parsed.approved_at,
    deniedAt: parsed.denied_at,
    lastPolledAt: parsed.last_polled_at,
    pollCount: parsed.poll_count,
    createdAt: parsed.created_at,
  }
}

export async function listDeviceSessions(
  env: Env,
  limit: number,
  offset: number,
): Promise<AdminDeviceSession[]> {
  const result = await env.DB.prepare(
    `SELECT ${COLUMNS} FROM device_authorization_sessions ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(limit, offset)
    .all()
  return result.results.map(mapRow)
}

export async function getDeviceSessionById(
  env: Env,
  id: string,
): Promise<AdminDeviceSession | null> {
  const row = await env.DB.prepare(
    `SELECT ${COLUMNS} FROM device_authorization_sessions WHERE id = ?`,
  )
    .bind(id)
    .first()
  return row === null ? null : mapRow(row)
}

export async function countDeviceSessions(env: Env): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM device_authorization_sessions",
  ).first()
  const parsed = z.object({ n: z.number() }).safeParse(row)
  return parsed.success ? parsed.data.n : 0
}

export async function revokeDeviceSession(env: Env, id: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE device_authorization_sessions SET status = 'denied', denied_at = ? WHERE id = ? AND status IN ('pending', 'approved')",
  )
    .bind(nowSeconds(), id)
    .run()
  return result.meta.changes === 1
}
