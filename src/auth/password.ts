import { z } from "zod"
import { hashPassword, verifyPassword } from "../security/crypto"
import { revokeRefreshFamilyDurableObjects } from "../tokens/refresh-token-revocation"
import { nowSeconds } from "../utils/time"

// A syntactically valid, non-secret scrypt record used when an account or
// credential is absent so login failure timing still performs equivalent work.
const DUMMY_PASSWORD_HASH =
  "scrypt$32768$8$1$yVLhH6oa6f3is1oUx0mLCg$iev7MtM5HU75bcTn8fv3AVGHeTZQg4sx-AlPLAWHJMA"

export async function setUserPassword(env: Env, userId: string, password: string): Promise<void> {
  const passwordHash = await hashPassword(password)
  const now = nowSeconds()
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO password_credentials (user_id, password_hash, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at`,
    ).bind(userId, passwordHash, now),
    env.DB.prepare(
      "UPDATE users SET security_version = security_version + 1, updated_at = ? WHERE id = ?",
    ).bind(now, userId),
  ])
}

/**
 * Change an authenticated user's password while keeping only the current
 * browser session and its attached refresh families. D1 commits the
 * credential, security epoch, session revocations, and refresh mirrors as one
 * transaction; Durable Objects are notified only after that commit.
 */
export async function changeUserPasswordKeepingSession(
  env: Env,
  userId: string,
  password: string,
  keepSessionId: string,
): Promise<boolean> {
  const passwordHash = await hashPassword(password)
  const now = nowSeconds()
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO password_credentials (user_id, password_hash, updated_at)
       SELECT id, ?, ? FROM users WHERE id = ? AND disabled = 0
       ON CONFLICT(user_id) DO UPDATE SET
         password_hash = excluded.password_hash, updated_at = excluded.updated_at`,
    ).bind(passwordHash, now, userId),
    env.DB.prepare(
      `UPDATE users SET security_version = security_version + 1, updated_at = ?
       WHERE id = ? AND disabled = 0`,
    ).bind(now, userId),
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE user_id = ? AND id != ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN password_credentials pc ON pc.user_id = u.id
           WHERE u.id = ? AND u.updated_at = ? AND pc.password_hash = ?
         )`,
    ).bind(now, userId, keepSessionId, userId, now, passwordHash),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND (session_id IS NULL OR session_id != ?) AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN password_credentials pc ON pc.user_id = u.id
           WHERE u.id = ? AND u.updated_at = ? AND pc.password_hash = ?
         )
       RETURNING id`,
    ).bind(now, userId, keepSessionId, userId, now, passwordHash),
  ])
  const refreshFamilyIds = z
    .array(z.object({ id: z.string() }))
    .parse(results[3]?.results ?? [])
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds)
  return results[0]?.meta.changes === 1 && results[1]?.meta.changes === 1
}

/** Set a reset password only if no security transition occurred since issue. */
export async function setUserPasswordAtSecurityVersion(
  env: Env,
  userId: string,
  password: string,
  expectedSecurityVersion: number,
  options: { readonly verifyEmail?: boolean } = {},
): Promise<boolean> {
  const passwordHash = await hashPassword(password)
  const now = nowSeconds()
  // D1 batch is one transaction: the credential/security epoch and every D1
  // access mirror either change together or roll back together.
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO password_credentials (user_id, password_hash, updated_at)
       SELECT id, ?, ? FROM users WHERE id = ? AND disabled = 0 AND security_version = ?
       ON CONFLICT(user_id) DO UPDATE SET
         password_hash = excluded.password_hash, updated_at = excluded.updated_at`,
    ).bind(passwordHash, now, userId, expectedSecurityVersion),
    env.DB.prepare(
      `UPDATE users
       SET security_version = security_version + 1,
           email_verified = CASE WHEN ? = 1 THEN 1 ELSE email_verified END,
           updated_at = ?
       WHERE id = ? AND disabled = 0 AND security_version = ?`,
    ).bind(options.verifyEmail === true ? 1 : 0, now, userId, expectedSecurityVersion),
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN password_credentials pc ON pc.user_id = u.id
           WHERE u.id = ? AND u.security_version = ? AND pc.password_hash = ?
         )`,
    ).bind(now, userId, userId, expectedSecurityVersion + 1, passwordHash),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN password_credentials pc ON pc.user_id = u.id
           WHERE u.id = ? AND u.security_version = ? AND pc.password_hash = ?
         )
       RETURNING id`,
    ).bind(now, userId, userId, expectedSecurityVersion + 1, passwordHash),
  ])
  const refreshFamilyIds = z
    .array(z.object({ id: z.string() }))
    .parse(results[3]?.results ?? [])
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds)
  return results[0]?.meta.changes === 1 && results[1]?.meta.changes === 1
}

export async function verifyUserPassword(
  env: Env,
  userId: string,
  password: string,
): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT password_hash FROM password_credentials WHERE user_id = ?",
  )
    .bind(userId)
    .first()
  if (row === null) {
    return false
  }
  const parsed = z.object({ password_hash: z.string() }).safeParse(row)
  if (!parsed.success) {
    return false
  }
  return verifyPassword(password, parsed.data.password_hash)
}

/** Verify a login password without exposing account existence through scrypt timing. */
export async function verifyLoginPassword(
  env: Env,
  userId: string | null,
  password: string,
): Promise<boolean> {
  const row =
    userId === null
      ? null
      : await env.DB.prepare("SELECT password_hash FROM password_credentials WHERE user_id = ?")
          .bind(userId)
          .first()
  const parsed = z.object({ password_hash: z.string() }).safeParse(row)
  const verified = await verifyPassword(
    password.length <= 128 ? password : "test-invalid-overlong-password",
    parsed.success ? parsed.data.password_hash : DUMMY_PASSWORD_HASH,
  )
  return password.length <= 128 && parsed.success && verified
}

export async function userHasPassword(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT 1 AS present FROM password_credentials WHERE user_id = ?",
  )
    .bind(userId)
    .first()
  return row !== null
}
