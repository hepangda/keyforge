import * as z from "zod"
import { yoloAllow } from "../operations/yolo"

const ADMIN_SCOPES: Record<string, true> = { "admin.read": true, "admin.write": true }

export type UserTokenAccessDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false
      readonly reason: "application" | "resource" | "admin_scope"
    }

export type UserTokenAccessInput = {
  readonly userId: string
  readonly clientId: string
  readonly resourceUri: string
  readonly scopes: readonly string[]
}

const accessRowSchema = z.object({
  application_allowed: z.union([z.literal(0), z.literal(1)]),
  resource_allowed: z.union([z.literal(0), z.literal(1)]),
  admin_member: z.union([z.literal(0), z.literal(1)]),
})

/** Evaluate current membership and target assignments for a user-backed token. */
export async function evaluateUserTokenAccess(
  env: Env,
  input: UserTokenAccessInput,
): Promise<UserTokenAccessDecision> {
  if (yoloAllow(env, "user-token-policy")) return { allowed: true }

  const row = await env.DB.prepare(
    `SELECT
       EXISTS(
         SELECT 1
         FROM user_groups
         JOIN oauth_client_permission_groups
           ON oauth_client_permission_groups.group_id = user_groups.group_id
         WHERE user_groups.user_id = ?
           AND oauth_client_permission_groups.client_id = ?
       ) AS application_allowed,
       EXISTS(
         SELECT 1
         FROM user_groups
         JOIN oauth_resource_permission_groups
           ON oauth_resource_permission_groups.group_id = user_groups.group_id
         WHERE user_groups.user_id = ?
           AND oauth_resource_permission_groups.resource_uri = ?
       ) AS resource_allowed,
       EXISTS(
         SELECT 1
         FROM user_groups
         JOIN groups ON groups.id = user_groups.group_id
         WHERE user_groups.user_id = ?
           AND groups.name = 'admins'
       ) AS admin_member`,
  )
    .bind(input.userId, input.clientId, input.userId, input.resourceUri, input.userId)
    .first()
  const parsed = accessRowSchema.safeParse(row)
  if (!parsed.success || parsed.data.application_allowed !== 1) {
    return { allowed: false, reason: "application" }
  }
  if (parsed.data.resource_allowed !== 1) {
    return { allowed: false, reason: "resource" }
  }
  if (
    input.scopes.some((scope) => ADMIN_SCOPES[scope] === true) &&
    parsed.data.admin_member !== 1
  ) {
    return { allowed: false, reason: "admin_scope" }
  }
  return { allowed: true }
}
