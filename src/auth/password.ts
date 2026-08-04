import { z } from "zod"
import { getUserById, isUserAdmin } from "../db/queries/users"
import { isYoloEnabled, noteYoloBypass } from "../operations/yolo"
import { hashPassword, verifyPassword } from "../security/crypto"
import { revokeRefreshFamilyDurableObjects } from "../tokens/refresh-token-revocation"
import { generateId, ID_PREFIX } from "../utils/id"
import { nowSeconds } from "../utils/time"

// A syntactically valid, non-secret scrypt record used when an account or
// credential is absent so login failure timing still performs equivalent work.
const DUMMY_PASSWORD_HASH =
  "scrypt$32768$8$1$yVLhH6oa6f3is1oUx0mLCg$iev7MtM5HU75bcTn8fv3AVGHeTZQg4sx-AlPLAWHJMA"

export const PASSWORD_POLICY = {
  standardMinimum: 6,
  administratorMinimum: 12,
  maximum: 128,
  maximumCredentials: 5,
} as const

export function minimumPasswordLength(administrator: boolean): number {
  return administrator ? PASSWORD_POLICY.administratorMinimum : PASSWORD_POLICY.standardMinimum
}

export function passwordMeetsPolicy(password: string, administrator: boolean): boolean {
  return (
    password.length >= minimumPasswordLength(administrator) &&
    password.length <= PASSWORD_POLICY.maximum
  )
}

/**
 * Policy check for the storage paths. YOLO mode drops the length floor but
 * keeps the ceiling, because an unbounded password is a hashing-cost problem
 * rather than a policy opinion.
 */
function passwordAcceptable(env: Env, password: string, administrator: boolean): boolean {
  if (isYoloEnabled(env)) return password.length <= PASSWORD_POLICY.maximum
  return passwordMeetsPolicy(password, administrator)
}

function adminEligible(password: string): boolean {
  return password.length >= PASSWORD_POLICY.administratorMinimum
}

export type PasswordCredentialSummary = {
  readonly id: string
  readonly name: string | null
  readonly adminEligible: boolean
  readonly createdAt: number
  readonly updatedAt: number
  readonly lastUsedAt: number | null
}

const passwordRowSchema = z.object({
  id: z.string(),
  password_hash: z.string(),
  admin_eligible: z.number(),
})

const passwordSummaryRowSchema = z.object({
  id: z.string(),
  name: z.string().nullable(),
  admin_eligible: z.number(),
  created_at: z.number(),
  updated_at: z.number(),
  last_used_at: z.number().nullable(),
})

async function passwordRows(
  env: Env,
  userId: string,
): Promise<z.infer<typeof passwordRowSchema>[]> {
  const result = await env.DB.prepare(
    `SELECT id, password_hash, admin_eligible
     FROM password_credentials
     WHERE user_id = ?
     ORDER BY created_at ASC
     LIMIT ?`,
  )
    .bind(userId, PASSWORD_POLICY.maximumCredentials)
    .all()
  return z.array(passwordRowSchema).parse(result.results)
}

export async function listPasswordCredentials(
  env: Env,
  userId: string,
): Promise<PasswordCredentialSummary[]> {
  const result = await env.DB.prepare(
    `SELECT id, name, admin_eligible, created_at, updated_at, last_used_at
     FROM password_credentials
     WHERE user_id = ?
     ORDER BY created_at ASC`,
  )
    .bind(userId)
    .all()
  return z
    .array(passwordSummaryRowSchema)
    .parse(result.results)
    .map((row) => ({
      id: row.id,
      name: row.name,
      adminEligible: row.admin_eligible === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastUsedAt: row.last_used_at,
    }))
}

/** Replace every password credential. Intended for provisioning and recovery. */
export async function setUserPassword(
  env: Env,
  userId: string,
  password: string,
  name = "Password",
): Promise<void> {
  const administrator = await isUserAdmin(env, userId)
  if (!passwordAcceptable(env, password, administrator)) {
    throw new RangeError(
      `password must contain ${minimumPasswordLength(administrator)}–${PASSWORD_POLICY.maximum} characters`,
    )
  }
  const passwordHash = await hashPassword(password)
  const id = generateId(ID_PREFIX.password)
  const now = nowSeconds()
  await env.DB.batch([
    env.DB.prepare("DELETE FROM password_credentials WHERE user_id = ?").bind(userId),
    env.DB.prepare(
      `INSERT INTO password_credentials
         (id, user_id, password_hash, name, admin_eligible, created_at, updated_at)
       SELECT ?, id, ?, ?, ?, ?, ? FROM users WHERE id = ?`,
    ).bind(id, passwordHash, name.slice(0, 80), adminEligible(password) ? 1 : 0, now, now, userId),
    env.DB.prepare(
      "UPDATE users SET security_version = security_version + 1, updated_at = ? WHERE id = ?",
    ).bind(now, userId),
  ])
}

export type AddPasswordResult = { readonly id: string } | null

/** Add another independently manageable password login method. */
export async function addUserPassword(
  env: Env,
  userId: string,
  password: string,
  name: string | null,
): Promise<AddPasswordResult> {
  const administrator = await isUserAdmin(env, userId)
  if (!passwordAcceptable(env, password, administrator)) return null
  const passwordHash = await hashPassword(password)
  const id = generateId(ID_PREFIX.password)
  const now = nowSeconds()
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO password_credentials
         (id, user_id, password_hash, name, admin_eligible, created_at, updated_at)
       SELECT ?, id, ?, ?, ?, ?, ?
       FROM users
       WHERE id = ? AND disabled = 0
         AND (SELECT COUNT(*) FROM password_credentials WHERE user_id = ?) < ?
       RETURNING id`,
    ).bind(
      id,
      passwordHash,
      name === null ? null : name.slice(0, 80),
      adminEligible(password) ? 1 : 0,
      now,
      now,
      userId,
      userId,
      PASSWORD_POLICY.maximumCredentials,
    ),
    env.DB.prepare(
      `UPDATE users SET security_version = security_version + 1, updated_at = ?
       WHERE id = ? AND EXISTS (SELECT 1 FROM password_credentials WHERE id = ? AND user_id = ?)`,
    ).bind(now, userId, id, userId),
  ])
  return results[0]?.meta.changes === 1 && results[1]?.meta.changes === 1 ? { id } : null
}

/** Set a recovery password only if no security transition occurred since issue. */
export async function setUserPasswordAtSecurityVersion(
  env: Env,
  userId: string,
  password: string,
  expectedSecurityVersion: number,
  options: { readonly verifyEmail?: boolean } = {},
): Promise<boolean> {
  const administrator = await isUserAdmin(env, userId)
  if (!passwordAcceptable(env, password, administrator)) return false
  const passwordHash = await hashPassword(password)
  const credentialId = generateId(ID_PREFIX.password)
  const now = nowSeconds()
  // D1 batch is one transaction: old credentials, the replacement credential,
  // security epoch, and every D1 access mirror change together or roll back.
  const results = await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM password_credentials
       WHERE user_id = ?
         AND EXISTS (SELECT 1 FROM users WHERE id = ? AND disabled = 0 AND security_version = ?)`,
    ).bind(userId, userId, expectedSecurityVersion),
    env.DB.prepare(
      `INSERT INTO password_credentials
         (id, user_id, password_hash, name, admin_eligible, created_at, updated_at)
       SELECT ?, id, ?, 'Password', ?, ?, ?
       FROM users WHERE id = ? AND disabled = 0 AND security_version = ?`,
    ).bind(
      credentialId,
      passwordHash,
      adminEligible(password) ? 1 : 0,
      now,
      now,
      userId,
      expectedSecurityVersion,
    ),
    env.DB.prepare(
      `UPDATE users
       SET security_version = security_version + 1,
           email_verified = CASE WHEN ? = 1 THEN 1 ELSE email_verified END,
           updated_at = ?
       WHERE id = ? AND disabled = 0 AND security_version = ?
         AND EXISTS (SELECT 1 FROM password_credentials WHERE id = ? AND user_id = ?)`,
    ).bind(
      options.verifyEmail === true ? 1 : 0,
      now,
      userId,
      expectedSecurityVersion,
      credentialId,
      userId,
    ),
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN password_credentials pc ON pc.user_id = u.id
           WHERE u.id = ? AND u.security_version = ? AND pc.id = ?
         )`,
    ).bind(now, userId, userId, expectedSecurityVersion + 1, credentialId),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN password_credentials pc ON pc.user_id = u.id
           WHERE u.id = ? AND u.security_version = ? AND pc.id = ?
         )
       RETURNING id`,
    ).bind(now, userId, userId, expectedSecurityVersion + 1, credentialId),
  ])
  const refreshFamilyIds = z
    .array(z.object({ id: z.string() }))
    .parse(results[4]?.results ?? [])
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds)
  return results[1]?.meta.changes === 1 && results[2]?.meta.changes === 1
}

async function verifyRows(
  password: string,
  rows: readonly z.infer<typeof passwordRowSchema>[],
): Promise<z.infer<typeof passwordRowSchema> | null> {
  const boundedPassword =
    password.length <= PASSWORD_POLICY.maximum ? password : "test-invalid-overlong-password"
  const candidates =
    rows.length === 0 ? [{ id: "", password_hash: DUMMY_PASSWORD_HASH, admin_eligible: 1 }] : rows
  for (const row of candidates) {
    if (await verifyPassword(boundedPassword, row.password_hash)) {
      return password.length <= PASSWORD_POLICY.maximum && rows.length > 0 ? row : null
    }
  }
  return null
}

export async function verifyUserPassword(
  env: Env,
  userId: string,
  password: string,
): Promise<boolean> {
  if (isYoloEnabled(env) && (await yoloLoginNameMatches(env, userId, password))) {
    noteYoloBypass("user-password")
    return true
  }
  const administrator = await isUserAdmin(env, userId)
  const rows = (await passwordRows(env, userId)).filter(
    (row) => !administrator || row.admin_eligible === 1,
  )
  return (await verifyRows(password, rows)) !== null
}

/** Compare a login identifier and password for the YOLO shortcut. */
function yoloIdentifierMatchesPassword(identifier: string | undefined, password: string): boolean {
  if (identifier === undefined) return false
  return identifier.trim().toLowerCase() === password.trim().toLowerCase()
}

/**
 * True when the password repeats one of the account's own login names. Used
 * when the caller has a user id but no submitted identifier to compare against.
 */
async function yoloLoginNameMatches(env: Env, userId: string, password: string): Promise<boolean> {
  const user = await getUserById(env, userId)
  if (user === null) return false
  return (
    yoloIdentifierMatchesPassword(user.email, password) ||
    yoloIdentifierMatchesPassword(user.alias, password)
  )
}

/** Verify any eligible login password and update only the matched method. */
export async function verifyLoginPassword(
  env: Env,
  userId: string | null,
  password: string,
  identifier?: string,
): Promise<boolean> {
  // YOLO mode accepts a password that simply repeats the login identifier, for
  // an account that already exists. An unknown account still fails, so the
  // caller cannot conjure a subject out of nothing.
  if (
    isYoloEnabled(env) &&
    userId !== null &&
    yoloIdentifierMatchesPassword(identifier, password)
  ) {
    noteYoloBypass("login-password")
    return true
  }
  if (userId === null) {
    await verifyPassword(
      password.length <= PASSWORD_POLICY.maximum ? password : "test-invalid-overlong-password",
      DUMMY_PASSWORD_HASH,
    )
    return false
  }
  const administrator = await isUserAdmin(env, userId)
  const rows = (await passwordRows(env, userId)).filter(
    (row) => !administrator || row.admin_eligible === 1,
  )
  const matched = await verifyRows(password, rows)
  if (matched === null) return false
  await env.DB.prepare(
    "UPDATE password_credentials SET last_used_at = ? WHERE id = ? AND user_id = ?",
  )
    .bind(nowSeconds(), matched.id, userId)
    .run()
  return true
}

export async function renamePasswordCredential(
  env: Env,
  credentialId: string,
  userId: string,
  name: string | null,
): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE password_credentials SET name = ?, updated_at = ? WHERE id = ? AND user_id = ?",
  )
    .bind(name === null ? null : name.slice(0, 80), nowSeconds(), credentialId, userId)
    .run()
  return result.meta.changes === 1
}

export type ProtectedPasswordDeleteResult = "deleted" | "not_found" | "last_login_method"

export async function deletePasswordCredentialPreservingLoginMethod(
  env: Env,
  credentialId: string,
  userId: string,
): Promise<ProtectedPasswordDeleteResult> {
  const result = await env.DB.prepare(
    `DELETE FROM password_credentials
     WHERE id = ? AND user_id = ?
       AND (
         EXISTS (
           SELECT 1 FROM password_credentials other
           WHERE other.user_id = ? AND other.id != ?
         )
         OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = ?)
       )`,
  )
    .bind(credentialId, userId, userId, credentialId, userId)
    .run()
  if (result.meta.changes === 1) return "deleted"
  const exists = await env.DB.prepare(
    "SELECT 1 AS present FROM password_credentials WHERE id = ? AND user_id = ?",
  )
    .bind(credentialId, userId)
    .first()
  return exists === null ? "not_found" : "last_login_method"
}

export async function userHasPassword(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT 1 AS present FROM password_credentials WHERE user_id = ? LIMIT 1",
  )
    .bind(userId)
    .first()
  return row !== null
}
