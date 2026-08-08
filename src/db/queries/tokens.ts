import * as z from "zod"
import { nowSeconds } from "../../utils/time"

export type RefreshTokenRecord = {
  readonly familyId: string
  readonly userId: string
  readonly clientId: string
  readonly sessionId: string | null
  readonly resource: string
  readonly scope: string
  readonly authTime: number
  readonly expiresAt: number
  readonly revokedAt: number | null
}

const refreshRowSchema = z.object({
  id: z.string(),
  user_id: z.string(),
  client_id: z.string(),
  session_id: z.string().nullable(),
  resource: z.string(),
  scope: z.string(),
  auth_time: z.number(),
  expires_at: z.number(),
  revoked_at: z.number().nullable(),
})

export async function getRefreshTokenByHash(
  env: Env,
  tokenHash: string,
): Promise<RefreshTokenRecord | null> {
  const row = await env.DB.prepare(
    "SELECT id, user_id, client_id, session_id, resource, scope, auth_time, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?",
  )
    .bind(tokenHash)
    .first()
  if (row === null) {
    return null
  }
  const parsed = refreshRowSchema.safeParse(row)
  if (!parsed.success) {
    return null
  }
  return {
    familyId: parsed.data.id,
    userId: parsed.data.user_id,
    clientId: parsed.data.client_id,
    sessionId: parsed.data.session_id,
    resource: parsed.data.resource,
    scope: parsed.data.scope,
    authTime: parsed.data.auth_time,
    expiresAt: parsed.data.expires_at,
    revokedAt: parsed.data.revoked_at,
  }
}

/** Look up family metadata without trusting the opaque token suffix. */
export async function getRefreshTokenByFamilyId(
  env: Env,
  familyId: string,
): Promise<RefreshTokenRecord | null> {
  const row = await env.DB.prepare(
    "SELECT id, user_id, client_id, session_id, resource, scope, auth_time, expires_at, revoked_at FROM refresh_tokens WHERE id = ?",
  )
    .bind(familyId)
    .first()
  if (row === null) {
    return null
  }
  const parsed = refreshRowSchema.safeParse(row)
  if (!parsed.success) {
    return null
  }
  return {
    familyId: parsed.data.id,
    userId: parsed.data.user_id,
    clientId: parsed.data.client_id,
    sessionId: parsed.data.session_id,
    resource: parsed.data.resource,
    scope: parsed.data.scope,
    authTime: parsed.data.auth_time,
    expiresAt: parsed.data.expires_at,
    revokedAt: parsed.data.revoked_at,
  }
}

export async function markRefreshTokenRevoked(env: Env, familyId: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
  )
    .bind(nowSeconds(), familyId)
    .run()
}

export type DeviceRefreshFamilySummary = {
  readonly familyId: string
  readonly clientId: string
  readonly clientName: string
  readonly resource: string
  readonly createdAt: number
  readonly lastRotatedAt: number
  readonly expiresAt: number
}

export async function listDeviceRefreshFamiliesForUser(
  env: Env,
  userId: string,
): Promise<DeviceRefreshFamilySummary[]> {
  const result = await env.DB.prepare(
    `SELECT r.id AS family_id, r.client_id, c.name AS client_name, r.resource,
            r.created_at, r.last_rotated_at, r.expires_at
     FROM refresh_tokens r
     JOIN oauth_clients c ON c.client_id = r.client_id AND c.client_kind = 'device'
     WHERE r.user_id = ? AND r.session_id IS NULL AND r.revoked_at IS NULL AND r.expires_at > ?
     ORDER BY r.last_rotated_at DESC`,
  )
    .bind(userId, nowSeconds())
    .all()
  return z
    .array(
      z.object({
        family_id: z.string(),
        client_id: z.string(),
        client_name: z.string(),
        resource: z.string(),
        created_at: z.number(),
        last_rotated_at: z.number(),
        expires_at: z.number(),
      }),
    )
    .parse(result.results)
    .map((row) => ({
      familyId: row.family_id,
      clientId: row.client_id,
      clientName: row.client_name,
      resource: row.resource,
      createdAt: row.created_at,
      lastRotatedAt: row.last_rotated_at,
      expiresAt: row.expires_at,
    }))
}

export async function revokeDeviceRefreshFamily(
  env: Env,
  familyId: string,
  userId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE refresh_tokens SET revoked_at = ?
     WHERE id = ? AND user_id = ? AND session_id IS NULL AND revoked_at IS NULL`,
  )
    .bind(nowSeconds(), familyId, userId)
    .run()
  if (result.meta.changes !== 1) return false
  await env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke()
  return true
}
