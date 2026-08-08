import { z } from "zod"
import { revokeRefreshFamilyDurableObjects } from "../../tokens/refresh-token-revocation"
import type { User } from "../../types/domain"
import { asUserId } from "../../types/domain"
import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"
import {
  adminPromotionRevocationStatements,
  mirrorAdminPromotionRefreshRevocations,
} from "./admin-promotion"

const userRowSchema = z.object({
  id: z.string(),
  email: z.string(),
  alias: z.string(),
  email_verified: z.number(),
  name: z.string().nullable(),
  picture: z.string().nullable(),
  avatar_key: z.string().nullable(),
  avatar_content_type: z.string().nullable(),
  avatar_updated_at: z.number().nullable(),
  disabled: z.number(),
  created_at: z.number(),
})

const userSecurityRowSchema = userRowSchema.extend({
  security_version: z.number(),
})

const USER_COLUMNS =
  "id, email, alias, email_verified, name, picture, avatar_key, avatar_content_type, avatar_updated_at, disabled, created_at"

/** Keep administrative payloads bounded without coupling them to D1 placeholder limits. */
export const MAX_USER_GROUPS = 100
export const MAX_ALIAS_LENGTH = 64
export const ALIAS_PATTERN = /^[A-Za-z0-9_-]+$/

function mapUser(row: unknown): User {
  const parsed = userRowSchema.parse(row)
  return {
    id: asUserId(parsed.id),
    email: parsed.email,
    alias: parsed.alias,
    emailVerified: parsed.email_verified === 1,
    name: parsed.name,
    picture: parsed.picture,
    avatarKey: parsed.avatar_key,
    avatarContentType: parsed.avatar_content_type,
    avatarUpdatedAt: parsed.avatar_updated_at,
    disabled: parsed.disabled === 1,
    createdAt: parsed.created_at,
  }
}

export async function getUserById(env: Env, id: string): Promise<User | null> {
  const row = await env.DB.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`)
    .bind(id)
    .first()
  return row === null ? null : mapUser(row)
}

export async function getUserByEmail(env: Env, email: string): Promise<User | null> {
  const row = await env.DB.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE email = ?`)
    .bind(email.toLowerCase())
    .first()
  return row === null ? null : mapUser(row)
}

export async function getUserByAlias(env: Env, alias: string): Promise<User | null> {
  const row = await env.DB.prepare(
    `SELECT ${USER_COLUMNS} FROM users WHERE lower(alias) = lower(?)`,
  )
    .bind(alias)
    .first()
  return row === null ? null : mapUser(row)
}

/** Resolve the identifier accepted by the login form without changing email-only flows. */
export async function getUserByLogin(env: Env, login: string): Promise<User | null> {
  const normalized = login.trim().toLowerCase()
  const row = await env.DB.prepare(
    `SELECT ${USER_COLUMNS} FROM users
     WHERE email = ? OR lower(alias) = ?
     LIMIT 1`,
  )
    .bind(normalized, normalized)
    .first()
  return row === null ? null : mapUser(row)
}

export async function getUserSecurityVersion(env: Env, id: string): Promise<number | null> {
  const row = await env.DB.prepare("SELECT security_version FROM users WHERE id = ?")
    .bind(id)
    .first<{ security_version: number }>()
  return row?.security_version ?? null
}

export type CreateUserInput = {
  readonly email: string
  readonly alias?: string
  readonly name?: string | null
  readonly picture?: string | null
  readonly emailVerified?: boolean
}

function generatedAlias(email: string, id: string): string {
  const local =
    email
      .split("@", 1)[0]
      ?.replace(/[^A-Za-z0-9]/g, "")
      .slice(0, 48) || "user"
  const suffix = id.replace(/[^A-Za-z0-9]/g, "").slice(-10)
  return `${local}${suffix}`.slice(0, MAX_ALIAS_LENGTH)
}

export async function createUser(env: Env, input: CreateUserInput): Promise<User> {
  const id = generateId(ID_PREFIX.user)
  const email = input.email.toLowerCase()
  const alias = input.alias?.trim() || generatedAlias(email, id)
  if (!ALIAS_PATTERN.test(alias) || alias.length > MAX_ALIAS_LENGTH) {
    throw new RangeError(
      "alias must contain only English letters, numbers, hyphens, and underscores",
    )
  }
  const now = nowSeconds()
  const user: User = {
    id: asUserId(id),
    email,
    alias,
    emailVerified: input.emailVerified ?? false,
    name: input.name ?? null,
    picture: input.picture ?? null,
    avatarKey: null,
    avatarContentType: null,
    avatarUpdatedAt: null,
    disabled: false,
    createdAt: now,
  }
  await env.DB.prepare(
    `INSERT INTO users (id, email, alias, email_verified, name, picture, disabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
  )
    .bind(id, email, alias, user.emailVerified ? 1 : 0, user.name, user.picture, now, now)
    .run()
  return user
}

export async function getUserGroupNames(env: Env, userId: string): Promise<string[]> {
  const result = await env.DB.prepare(
    "SELECT g.name AS name FROM user_groups ug JOIN groups g ON g.id = ug.group_id WHERE ug.user_id = ?",
  )
    .bind(userId)
    .all()
  const parsed = z.array(z.object({ name: z.string() })).safeParse(result.results)
  return parsed.success ? parsed.data.map((entry) => entry.name) : []
}

export async function isUserAdmin(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare(
    `SELECT 1 AS present
     FROM user_groups ug
     JOIN groups g ON g.id = ug.group_id
     WHERE ug.user_id = ? AND g.name = 'admins'
     LIMIT 1`,
  )
    .bind(userId)
    .first()
  return row !== null
}

export async function getUserGroupIds(env: Env, userId: string): Promise<string[]> {
  const result = await env.DB.prepare(
    "SELECT group_id FROM user_groups WHERE user_id = ? ORDER BY group_id ASC",
  )
    .bind(userId)
    .all()
  const parsed = z.array(z.object({ group_id: z.string() })).safeParse(result.results)
  return parsed.success ? parsed.data.map((entry) => entry.group_id) : []
}

export async function listUsers(env: Env, limit: number, offset: number): Promise<User[]> {
  const result = await env.DB.prepare(
    `SELECT ${USER_COLUMNS} FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(limit, offset)
    .all()
  return result.results.map(mapUser)
}
function escapeLikePattern(value: string): string {
  return value.replace(/[\\%_]/g, "\\$&")
}

export async function searchUsers(
  env: Env,
  query: string,
  limit: number,
  offset: number,
): Promise<User[]> {
  const pattern = `%${escapeLikePattern(query.toLowerCase())}%`
  const result = await env.DB.prepare(
    `SELECT ${USER_COLUMNS} FROM users
     WHERE id = ?
        OR lower(email) LIKE ? ESCAPE '\\'
        OR lower(alias) LIKE ? ESCAPE '\\'
     ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(query, pattern, pattern, limit, offset)
    .all()
  return result.results.map(mapUser)
}

export async function countUsers(env: Env): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first()
  const parsed = z.object({ n: z.number() }).safeParse(row)
  return parsed.success ? parsed.data.n : 0
}

export type UserPatch = {
  readonly name?: string | null
  readonly disabled?: boolean
  readonly emailVerified?: boolean
}

export async function updateUser(env: Env, id: string, patch: UserPatch): Promise<User | null> {
  const currentRow = await env.DB.prepare(
    `SELECT ${USER_COLUMNS}, security_version FROM users WHERE id = ?`,
  )
    .bind(id)
    .first()
  if (currentRow === null) {
    return null
  }
  const parsedCurrent = userSecurityRowSchema.parse(currentRow)
  const current = mapUser(parsedCurrent)
  const next: User = {
    ...current,
    name: patch.name === undefined ? current.name : patch.name,
    disabled: patch.disabled ?? current.disabled,
    emailVerified: patch.emailVerified ?? current.emailVerified,
  }
  const now = nowSeconds()
  const disabledChanged = current.disabled !== next.disabled
  const expectedSecurityVersion = parsedCurrent.security_version + (disabledChanged ? 1 : 0)
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE users
       SET name = ?, security_version = security_version + ?,
           disabled = ?, email_verified = ?, updated_at = ?
       WHERE id = ? AND disabled = ? AND security_version = ?
         AND (
           ? = 0 OR disabled = 1
           OR NOT EXISTS (
             SELECT 1 FROM user_groups ug JOIN groups g ON g.id = ug.group_id
             WHERE ug.user_id = users.id AND g.name = 'admins'
           )
           OR EXISTS (
             SELECT 1 FROM user_groups other_ug
             JOIN groups other_g ON other_g.id = other_ug.group_id
             JOIN users other_u ON other_u.id = other_ug.user_id
             WHERE other_g.name = 'admins' AND other_u.disabled = 0 AND other_u.id != users.id
           )
         )
       RETURNING ${USER_COLUMNS}`,
    ).bind(
      next.name,
      disabledChanged ? 1 : 0,
      next.disabled ? 1 : 0,
      next.emailVerified ? 1 : 0,
      now,
      id,
      current.disabled ? 1 : 0,
      parsedCurrent.security_version,
      next.disabled ? 1 : 0,
    ),
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE ? = 1 AND user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           WHERE u.id = ? AND u.disabled = ? AND u.security_version = ? AND u.updated_at = ?
         )`,
    ).bind(
      now,
      disabledChanged ? 1 : 0,
      id,
      id,
      next.disabled ? 1 : 0,
      expectedSecurityVersion,
      now,
    ),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE ? = 1 AND user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           WHERE u.id = ? AND u.disabled = ? AND u.security_version = ? AND u.updated_at = ?
         )
       RETURNING id`,
    ).bind(
      now,
      disabledChanged ? 1 : 0,
      id,
      id,
      next.disabled ? 1 : 0,
      expectedSecurityVersion,
      now,
    ),
  ])
  const refreshFamilyIds = z
    .array(z.object({ id: z.string() }))
    .parse(results[2]?.results ?? [])
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds)
  const row = results[0]?.results[0]
  return row === undefined ? null : mapUser(row)
}

export type UpdateUserAliasResult = "updated" | "not_found" | "conflict"

/**
 * Point a user at a newly stored avatar object and report the object it
 * replaced, so the caller can delete the superseded bytes from R2.
 * Returns `undefined` when the user no longer exists.
 */
export async function setUserAvatar(
  env: Env,
  id: string,
  avatar: { readonly key: string; readonly contentType: string },
): Promise<string | null | undefined> {
  const now = nowSeconds()
  return await swapAvatar(
    env,
    id,
    `UPDATE users
     SET avatar_key = ?, avatar_content_type = ?, avatar_updated_at = ?, updated_at = ?
     WHERE id = ?`,
    [avatar.key, avatar.contentType, now, now, id],
  )
}

/** Remove a user's uploaded avatar, returning the object key that must be deleted. */
export async function clearUserAvatar(env: Env, id: string): Promise<string | null | undefined> {
  return await swapAvatar(
    env,
    id,
    `UPDATE users
     SET avatar_key = NULL, avatar_content_type = NULL, avatar_updated_at = NULL, updated_at = ?
     WHERE id = ?`,
    [nowSeconds(), id],
  )
}

/**
 * Apply an avatar mutation and report the previously referenced object key.
 * The prior key is read in the same batch as the update so a concurrent change
 * cannot make this caller delete an object the winning writer still points at:
 * the reader sees the value the update itself replaced.
 */
async function swapAvatar(
  env: Env,
  id: string,
  statement: string,
  bindings: readonly (string | number)[],
): Promise<string | null | undefined> {
  const results = await env.DB.batch([
    env.DB.prepare("SELECT avatar_key FROM users WHERE id = ?").bind(id),
    env.DB.prepare(statement).bind(...bindings),
  ])
  const previous = z
    .array(z.object({ avatar_key: z.string().nullable() }))
    .safeParse(results[0]?.results ?? [])
  if (!previous.success || previous.data.length === 0) return undefined
  return previous.data[0]?.avatar_key ?? null
}

/** Atomically change the administrator-managed sign-in name when it remains unique. */
export async function updateUserAlias(
  env: Env,
  id: string,
  alias: string,
): Promise<UpdateUserAliasResult> {
  const normalized = alias.trim()
  if (!ALIAS_PATTERN.test(normalized) || normalized.length > MAX_ALIAS_LENGTH) {
    return "conflict"
  }
  const result = await env.DB.prepare(
    `UPDATE users SET alias = ?, updated_at = ?
     WHERE id = ?
       AND NOT EXISTS (
         SELECT 1 FROM users other WHERE lower(other.alias) = lower(?) AND other.id != ?
       )`,
  )
    .bind(normalized, nowSeconds(), id, normalized, id)
    .run()
  if (result.meta.changes === 1) return "updated"
  return (await getUserById(env, id)) === null ? "not_found" : "conflict"
}

export type UpdateUserEmailResult = "updated" | "not_found" | "conflict"

/** Atomically change a login email only when no other account owns it. */
export async function updateUserEmail(
  env: Env,
  id: string,
  newEmail: string,
  expectedSecurityVersion: number,
): Promise<UpdateUserEmailResult> {
  const normalized = newEmail.trim().toLowerCase()
  const now = nowSeconds()
  // The email/security epoch and both revocation mirrors commit in one D1
  // transaction. The resulting family ids are mirrored to DOs afterward.
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE users
       SET email = ?, email_verified = 1, security_version = security_version + 1, updated_at = ?
       WHERE id = ? AND disabled = 0 AND security_version = ?
         AND NOT EXISTS (SELECT 1 FROM users AS other WHERE other.email = ? AND other.id != ?)`,
    ).bind(normalized, now, id, expectedSecurityVersion, normalized, id),
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           WHERE u.id = ? AND u.email = ? AND u.security_version = ? AND u.updated_at = ?
         )`,
    ).bind(now, id, id, normalized, expectedSecurityVersion + 1, now),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM users u
           WHERE u.id = ? AND u.email = ? AND u.security_version = ? AND u.updated_at = ?
         )
       RETURNING id`,
    ).bind(now, id, id, normalized, expectedSecurityVersion + 1, now),
  ])
  const refreshFamilyIds = z
    .array(z.object({ id: z.string() }))
    .parse(results[2]?.results ?? [])
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, refreshFamilyIds)
  if (results[0]?.meta.changes === 1) {
    return "updated"
  }
  const conflicting = await getUserByEmail(env, normalized)
  return conflicting !== null && conflicting.id !== id ? "conflict" : "not_found"
}

export async function deleteUser(env: Env, id: string): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run()
  return result.meta.changes === 1
}

/** Atomically delete unless this is the last active administrator. */
export async function deleteUserPreservingActiveAdmin(env: Env, id: string): Promise<boolean> {
  const deleted = await env.DB.prepare(
    `DELETE FROM users
     WHERE id = ?
       AND (
         disabled = 1
         OR NOT EXISTS (
           SELECT 1 FROM user_groups ug JOIN groups g ON g.id = ug.group_id
           WHERE ug.user_id = ? AND g.name = 'admins'
         )
         OR EXISTS (
           SELECT 1 FROM user_groups other_ug
           JOIN groups other_g ON other_g.id = other_ug.group_id
           JOIN users other_u ON other_u.id = other_ug.user_id
           WHERE other_g.name = 'admins' AND other_u.disabled = 0 AND other_u.id != ?
         )
       )
     RETURNING id`,
  )
    .bind(id, id, id)
    .first<{ id: string }>()
  return deleted !== null
}

export type GroupSummary = {
  readonly id: string
  readonly name: string
  readonly description: string | null
  readonly memberCount: number
}

const groupRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  member_count: z.number(),
})

function mapGroup(row: unknown): GroupSummary {
  const parsed = groupRowSchema.parse(row)
  return {
    id: parsed.id,
    name: parsed.name,
    description: parsed.description,
    memberCount: parsed.member_count,
  }
}

export async function listGroups(env: Env): Promise<GroupSummary[]> {
  const result = await env.DB.prepare(
    `SELECT g.id, g.name, g.description,
            (SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id) AS member_count
     FROM groups g ORDER BY g.name ASC`,
  ).all()
  return result.results.map(mapGroup)
}

export async function getGroupByName(env: Env, name: string): Promise<GroupSummary | null> {
  const row = await env.DB.prepare(
    `SELECT g.id, g.name, g.description,
            (SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id) AS member_count
     FROM groups g WHERE g.name = ?`,
  )
    .bind(name.trim().toLowerCase())
    .first()
  return row === null ? null : mapGroup(row)
}

export async function countUsersInGroup(env: Env, groupName: string): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM user_groups ug
     JOIN groups g ON g.id = ug.group_id WHERE g.name = ?`,
  )
    .bind(groupName)
    .first()
  const parsed = z.object({ n: z.number() }).safeParse(row)
  return parsed.success ? parsed.data.n : 0
}

/** True when removing this user's active admin access would leave no active administrator. */
export async function isSoleActiveAdmin(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n,
            MAX(CASE WHEN u.id = ? THEN 1 ELSE 0 END) AS includes_user
     FROM user_groups ug
     JOIN groups g ON g.id = ug.group_id
     JOIN users u ON u.id = ug.user_id
     WHERE g.name = 'admins' AND u.disabled = 0`,
  )
    .bind(userId)
    .first()
  const parsed = z.object({ n: z.number(), includes_user: z.number().nullable() }).safeParse(row)
  return parsed.success && parsed.data.n === 1 && parsed.data.includes_user === 1
}

export async function createGroup(
  env: Env,
  name: string,
  description: string | null,
): Promise<GroupSummary> {
  const group = {
    id: generateId(ID_PREFIX.group),
    name: name.trim().toLowerCase(),
    description,
    memberCount: 0,
  }
  await env.DB.prepare("INSERT INTO groups (id, name, description, created_at) VALUES (?, ?, ?, ?)")
    .bind(group.id, group.name, group.description, nowSeconds())
    .run()
  return group
}

export type GroupMutationResult = "updated" | "deleted" | "not_found" | "conflict" | "protected"

export async function updateGroup(
  env: Env,
  id: string,
  name: string,
  description: string | null,
): Promise<GroupMutationResult> {
  const normalized = name.trim().toLowerCase()
  const current = (await listGroups(env)).find((group) => group.id === id)
  if (current === undefined) return "not_found"
  if (current.name === "admins" && normalized !== "admins") return "protected"
  const result = await env.DB.prepare(
    `UPDATE groups SET name = ?, description = ?
     WHERE id = ? AND NOT EXISTS (SELECT 1 FROM groups other WHERE other.name = ? AND other.id != ?)`,
  )
    .bind(normalized, description, id, normalized, id)
    .run()
  return result.meta.changes === 1 ? "updated" : "conflict"
}

export async function deleteGroup(env: Env, id: string): Promise<GroupMutationResult> {
  const current = (await listGroups(env)).find((group) => group.id === id)
  if (current === undefined) return "not_found"
  if (current.name === "admins") return "protected"
  const result = await env.DB.prepare("DELETE FROM groups WHERE id = ? AND name != 'admins'")
    .bind(id)
    .run()
  return result.meta.changes >= 1 ? "deleted" : "not_found"
}

export async function setUserGroups(
  env: Env,
  userId: string,
  groupIds: readonly string[],
): Promise<void> {
  const now = nowSeconds()
  const unique = [...new Set(groupIds)]
  if (unique.length > MAX_USER_GROUPS) {
    throw new RangeError(`a user may belong to at most ${MAX_USER_GROUPS} groups`)
  }
  const desired = JSON.stringify(unique)
  const promotionRevocations = adminPromotionRevocationStatements(env, userId, now)
  const results = await env.DB.batch([
    env.DB.prepare(
      `WITH desired(group_id) AS (
         SELECT CAST(value AS TEXT) FROM json_each(?)
       )
       DELETE FROM user_groups
       WHERE user_id = ?
         AND NOT EXISTS (SELECT 1 FROM desired WHERE desired.group_id = user_groups.group_id)`,
    ).bind(desired, userId),
    env.DB.prepare(
      `WITH desired(group_id) AS (
         SELECT CAST(value AS TEXT) FROM json_each(?)
       )
       INSERT OR IGNORE INTO user_groups (user_id, group_id, created_at)
       SELECT ?, desired.group_id, ? FROM desired`,
    ).bind(desired, userId, now),
    ...promotionRevocations,
  ])
  await mirrorAdminPromotionRefreshRevocations(env, results[4]?.results)
}

/** Replace memberships while atomically preserving one active administrator. */
export async function setUserGroupsPreservingActiveAdmin(
  env: Env,
  userId: string,
  groupIds: readonly string[],
): Promise<boolean> {
  const now = nowSeconds()
  const unique = [...new Set(groupIds)]
  if (unique.length > MAX_USER_GROUPS) {
    throw new RangeError(`a user may belong to at most ${MAX_USER_GROUPS} groups`)
  }
  const desired = JSON.stringify(unique)
  // Both statements use the same predicate inside one transactional D1 batch.
  // Inserts run first, so a rejected sole-admin demotion cannot partially
  // remove memberships before the guard is evaluated.
  const replacementIsSafe = `(
    EXISTS (
      SELECT 1
      FROM desired
      JOIN groups desired_group ON desired_group.id = desired.group_id
      WHERE desired_group.name = 'admins'
    )
    OR NOT EXISTS (
      SELECT 1
      FROM user_groups target_ug
      JOIN groups target_g ON target_g.id = target_ug.group_id
      JOIN users target_u ON target_u.id = target_ug.user_id
      WHERE target_ug.user_id = ?
        AND target_g.name = 'admins'
        AND target_u.disabled = 0
        AND NOT EXISTS (
          SELECT 1
          FROM user_groups other_ug
          JOIN groups other_g ON other_g.id = other_ug.group_id
          JOIN users other_u ON other_u.id = other_ug.user_id
          WHERE other_g.name = 'admins'
            AND other_u.disabled = 0
            AND other_u.id != target_ug.user_id
        )
    )
  )`
  const promotionRevocations = adminPromotionRevocationStatements(env, userId, now)
  const results = await env.DB.batch([
    env.DB.prepare(
      `WITH desired(group_id) AS (
         SELECT CAST(value AS TEXT) FROM json_each(?)
       )
       INSERT OR IGNORE INTO user_groups (user_id, group_id, created_at)
       SELECT ?, desired.group_id, ?
       FROM desired
       WHERE ${replacementIsSafe}`,
    ).bind(desired, userId, now, userId),
    env.DB.prepare(
      `WITH desired(group_id) AS (
         SELECT CAST(value AS TEXT) FROM json_each(?)
       )
       DELETE FROM user_groups
       WHERE user_id = ?
         AND NOT EXISTS (SELECT 1 FROM desired WHERE desired.group_id = user_groups.group_id)
         AND ${replacementIsSafe}`,
    ).bind(desired, userId, userId),
    ...promotionRevocations,
  ])
  await mirrorAdminPromotionRefreshRevocations(env, results[4]?.results)
  const actual = await getUserGroupIds(env, userId)
  return actual.length === unique.length && actual.every((id) => unique.includes(id))
}
