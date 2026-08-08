import { z } from "zod"
import { nowSeconds } from "../../utils/time"
import {
  adminPromotionRevocationStatements,
  mirrorAdminPromotionRefreshRevocations,
} from "./admin-promotion"
import { MAX_USER_GROUPS } from "./users"

export type PermissionGroupMembershipSummary = {
  readonly id: string
  readonly name: string
  readonly description: string | null
  readonly memberCount: number
  readonly state: "member" | "pending" | "available"
}

const membershipSummaryRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  member_count: z.number(),
  state: z.enum(["member", "pending", "available"]),
})

export async function listPermissionGroupsForUser(
  env: Env,
  userId: string,
): Promise<PermissionGroupMembershipSummary[]> {
  const result = await env.DB.prepare(
    `SELECT g.id, g.name, g.description,
            (SELECT COUNT(*) FROM user_groups members WHERE members.group_id = g.id) AS member_count,
            CASE
              WHEN EXISTS (
                SELECT 1 FROM user_groups membership
                WHERE membership.user_id = ? AND membership.group_id = g.id
              ) THEN 'member'
              WHEN EXISTS (
                SELECT 1 FROM group_membership_requests request
                WHERE request.user_id = ? AND request.group_id = g.id
              ) THEN 'pending'
              ELSE 'available'
            END AS state
     FROM groups g
     WHERE g.name != 'admins'
        OR EXISTS (
          SELECT 1 FROM user_groups membership
          WHERE membership.user_id = ? AND membership.group_id = g.id
        )
     ORDER BY CASE state WHEN 'member' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, g.name ASC`,
  )
    .bind(userId, userId, userId)
    .all()
  return z
    .array(membershipSummaryRowSchema)
    .parse(result.results)
    .map((row) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      memberCount: row.member_count,
      state: row.state,
    }))
}

export type MembershipRequestResult =
  | "requested"
  | "already_member"
  | "already_pending"
  | "not_found"
  | "protected"

const requestTargetSchema = z.object({
  name: z.string(),
  is_member: z.number(),
  is_pending: z.number(),
})

export async function requestPermissionGroupMembership(
  env: Env,
  userId: string,
  groupId: string,
): Promise<MembershipRequestResult> {
  const row = await env.DB.prepare(
    `SELECT g.name,
            EXISTS(
              SELECT 1 FROM user_groups
              WHERE user_id = ? AND group_id = g.id
            ) AS is_member,
            EXISTS(
              SELECT 1 FROM group_membership_requests
              WHERE user_id = ? AND group_id = g.id
            ) AS is_pending
     FROM groups g
     WHERE g.id = ?`,
  )
    .bind(userId, userId, groupId)
    .first()
  if (row === null) return "not_found"
  const target = requestTargetSchema.parse(row)
  if (target.name === "admins") return "protected"
  if (target.is_member === 1) return "already_member"
  if (target.is_pending === 1) return "already_pending"

  const inserted = await env.DB.prepare(
    `INSERT OR IGNORE INTO group_membership_requests (user_id, group_id, requested_at)
     SELECT ?, g.id, unixepoch()
     FROM groups g
     WHERE g.id = ? AND g.name != 'admins'
       AND NOT EXISTS (
         SELECT 1 FROM user_groups
         WHERE user_id = ? AND group_id = g.id
       )`,
  )
    .bind(userId, groupId, userId)
    .run()
  return inserted.meta.changes === 1 ? "requested" : "not_found"
}

export async function cancelPermissionGroupMembershipRequest(
  env: Env,
  userId: string,
  groupId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    "DELETE FROM group_membership_requests WHERE user_id = ? AND group_id = ?",
  )
    .bind(userId, groupId)
    .run()
  return result.meta.changes === 1
}

export type GroupMemberSummary = {
  readonly userId: string
  readonly email: string
  readonly alias: string
  readonly name: string | null
  readonly disabled: boolean
  readonly joinedAt: number
}

export type GroupMembershipRequestSummary = Omit<GroupMemberSummary, "joinedAt"> & {
  readonly requestedAt: number
}

const memberRowSchema = z.object({
  user_id: z.string(),
  email: z.string(),
  alias: z.string(),
  name: z.string().nullable(),
  disabled: z.number(),
  joined_at: z.number(),
})

const requestRowSchema = memberRowSchema.omit({ joined_at: true }).extend({
  requested_at: z.number(),
})

function mapMember(row: z.infer<typeof memberRowSchema>): GroupMemberSummary {
  return {
    userId: row.user_id,
    email: row.email,
    alias: row.alias,
    name: row.name,
    disabled: row.disabled === 1,
    joinedAt: row.joined_at,
  }
}

export async function listGroupMembers(
  env: Env,
  groupId: string,
  limit: number,
  offset: number,
): Promise<GroupMemberSummary[]> {
  const result = await env.DB.prepare(
    `SELECT u.id AS user_id, u.email, u.alias, u.name, u.disabled, membership.created_at AS joined_at
     FROM user_groups membership
     JOIN users u ON u.id = membership.user_id
     WHERE membership.group_id = ?
     ORDER BY u.disabled ASC, lower(u.alias) ASC, u.id ASC
     LIMIT ? OFFSET ?`,
  )
    .bind(groupId, limit, offset)
    .all()
  return z.array(memberRowSchema).parse(result.results).map(mapMember)
}

export async function listPendingGroupMembershipRequests(
  env: Env,
  groupId: string,
  limit: number,
): Promise<GroupMembershipRequestSummary[]> {
  const result = await env.DB.prepare(
    `SELECT u.id AS user_id, u.email, u.alias, u.name, u.disabled,
            request.requested_at
     FROM group_membership_requests request
     JOIN users u ON u.id = request.user_id
     WHERE request.group_id = ?
       AND NOT EXISTS (
         SELECT 1 FROM user_groups membership
         WHERE membership.user_id = request.user_id
           AND membership.group_id = request.group_id
       )
     ORDER BY request.requested_at ASC, u.id ASC
     LIMIT ?`,
  )
    .bind(groupId, limit)
    .all()
  return z
    .array(requestRowSchema)
    .parse(result.results)
    .map((row) => ({
      userId: row.user_id,
      email: row.email,
      alias: row.alias,
      name: row.name,
      disabled: row.disabled === 1,
      requestedAt: row.requested_at,
    }))
}

export type GroupMemberCandidate = Omit<GroupMemberSummary, "joinedAt">

const candidateRowSchema = memberRowSchema.omit({ joined_at: true })

export async function searchGroupMemberCandidates(
  env: Env,
  groupId: string,
  query: string,
  limit: number,
): Promise<GroupMemberCandidate[]> {
  const normalized = query.trim().toLowerCase()
  const result = await env.DB.prepare(
    `SELECT u.id AS user_id, u.email, u.alias, u.name, u.disabled
     FROM users u
     WHERE NOT EXISTS (
       SELECT 1 FROM user_groups membership
       WHERE membership.user_id = u.id AND membership.group_id = ?
     )
       AND (
         ? = ''
         OR u.id = ?
         OR instr(lower(u.email), ?) > 0
         OR instr(lower(u.alias), ?) > 0
         OR instr(lower(COALESCE(u.name, '')), ?) > 0
       )
     ORDER BY
       CASE WHEN lower(u.email) = ? OR lower(u.alias) = ? THEN 0 ELSE 1 END,
       u.disabled ASC,
       u.created_at DESC
     LIMIT ?`,
  )
    .bind(
      groupId,
      normalized,
      query.trim(),
      normalized,
      normalized,
      normalized,
      normalized,
      normalized,
      limit,
    )
    .all()
  return z
    .array(candidateRowSchema)
    .parse(result.results)
    .map((row) => ({
      userId: row.user_id,
      email: row.email,
      alias: row.alias,
      name: row.name,
      disabled: row.disabled === 1,
    }))
}

export type AddGroupMemberResult = "added" | "already_member" | "not_found" | "limit" | "no_request"

const addStateSchema = z.object({
  user_exists: z.number(),
  group_exists: z.number(),
  is_member: z.number(),
  has_request: z.number(),
  group_count: z.number(),
})

async function addGroupMember(
  env: Env,
  groupId: string,
  userId: string,
  requireRequest: boolean,
): Promise<AddGroupMemberResult> {
  const now = nowSeconds()
  const revocations = adminPromotionRevocationStatements(env, userId, now)
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT OR IGNORE INTO user_groups (user_id, group_id, created_at)
       SELECT u.id, g.id, ?
       FROM users u CROSS JOIN groups g
       WHERE u.id = ? AND g.id = ?
         AND (
           ? = 0
           OR EXISTS (
             SELECT 1 FROM group_membership_requests request
             WHERE request.user_id = u.id AND request.group_id = g.id
           )
         )
         AND (SELECT COUNT(*) FROM user_groups WHERE user_id = u.id) < ?`,
    ).bind(now, userId, groupId, requireRequest ? 1 : 0, MAX_USER_GROUPS),
    ...revocations,
  ])
  const inserted = results[0]
  await mirrorAdminPromotionRefreshRevocations(env, results[3]?.results)
  if ((inserted?.meta.changes ?? 0) >= 1) {
    await env.DB.prepare("DELETE FROM group_membership_requests WHERE user_id = ? AND group_id = ?")
      .bind(userId, groupId)
      .run()
    return "added"
  }

  const row = await env.DB.prepare(
    `SELECT
       EXISTS(SELECT 1 FROM users WHERE id = ?) AS user_exists,
       EXISTS(SELECT 1 FROM groups WHERE id = ?) AS group_exists,
       EXISTS(
         SELECT 1 FROM user_groups WHERE user_id = ? AND group_id = ?
       ) AS is_member,
       EXISTS(
         SELECT 1 FROM group_membership_requests WHERE user_id = ? AND group_id = ?
       ) AS has_request,
       (SELECT COUNT(*) FROM user_groups WHERE user_id = ?) AS group_count`,
  )
    .bind(userId, groupId, userId, groupId, userId, groupId, userId)
    .first()
  const state = addStateSchema.parse(row)
  if (state.user_exists !== 1 || state.group_exists !== 1) return "not_found"
  if (requireRequest && state.has_request !== 1) return "no_request"
  if (state.is_member === 1) {
    await env.DB.prepare("DELETE FROM group_membership_requests WHERE user_id = ? AND group_id = ?")
      .bind(userId, groupId)
      .run()
    return "already_member"
  }
  return state.group_count >= MAX_USER_GROUPS ? "limit" : "not_found"
}

export async function addUserToPermissionGroup(
  env: Env,
  groupId: string,
  userId: string,
): Promise<AddGroupMemberResult> {
  return addGroupMember(env, groupId, userId, false)
}

export async function approvePermissionGroupMembershipRequest(
  env: Env,
  groupId: string,
  userId: string,
): Promise<AddGroupMemberResult> {
  return addGroupMember(env, groupId, userId, true)
}

export async function rejectPermissionGroupMembershipRequest(
  env: Env,
  groupId: string,
  userId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    "DELETE FROM group_membership_requests WHERE user_id = ? AND group_id = ?",
  )
    .bind(userId, groupId)
    .run()
  return result.meta.changes === 1
}

export type RemoveGroupMemberResult = "removed" | "not_member" | "last_admin"

export async function removeUserFromPermissionGroup(
  env: Env,
  groupId: string,
  userId: string,
): Promise<RemoveGroupMemberResult> {
  const removed = await env.DB.prepare(
    `DELETE FROM user_groups
     WHERE user_id = ? AND group_id = ?
       AND (
         NOT EXISTS (
           SELECT 1 FROM groups target_group
           WHERE target_group.id = user_groups.group_id
             AND target_group.name = 'admins'
         )
         OR EXISTS (
           SELECT 1 FROM users target_user
           WHERE target_user.id = user_groups.user_id
             AND target_user.disabled = 1
         )
         OR EXISTS (
           SELECT 1
           FROM user_groups other_membership
           JOIN groups other_group ON other_group.id = other_membership.group_id
           JOIN users other_user ON other_user.id = other_membership.user_id
           WHERE other_group.name = 'admins'
             AND other_user.disabled = 0
             AND other_user.id != user_groups.user_id
         )
       )`,
  )
    .bind(userId, groupId)
    .run()
  if (removed.meta.changes === 1) return "removed"
  const membership = await env.DB.prepare(
    "SELECT 1 AS present FROM user_groups WHERE user_id = ? AND group_id = ?",
  )
    .bind(userId, groupId)
    .first()
  return membership === null ? "not_member" : "last_admin"
}
