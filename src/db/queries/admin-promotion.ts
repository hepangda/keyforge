import * as z from "zod"
import { revokeRefreshFamilyDurableObjects } from "../../tokens/refresh-token-revocation"

const ADMIN_PROMOTION_PREDICATE = `EXISTS (
  SELECT 1
  FROM user_groups promotion
  JOIN groups promoted_group ON promoted_group.id = promotion.group_id
  WHERE promotion.user_id = ?
    AND promoted_group.name = 'admins'
    AND promotion.created_at = ?
)`

export function adminPromotionRevocationStatements(
  env: Env,
  userId: string,
  membershipCreatedAt: number,
) {
  return [
    env.DB.prepare(
      `UPDATE users
       SET security_version = security_version + 1, updated_at = ?
       WHERE id = ? AND ${ADMIN_PROMOTION_PREDICATE}`,
    ).bind(membershipCreatedAt, userId, userId, membershipCreatedAt),
    env.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND ${ADMIN_PROMOTION_PREDICATE}`,
    ).bind(membershipCreatedAt, userId, userId, membershipCreatedAt),
    env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE user_id = ? AND revoked_at IS NULL
         AND ${ADMIN_PROMOTION_PREDICATE}
       RETURNING id`,
    ).bind(membershipCreatedAt, userId, userId, membershipCreatedAt),
  ] as const
}

export async function mirrorAdminPromotionRefreshRevocations(
  env: Env,
  rows: unknown,
): Promise<void> {
  const familyIds = z
    .array(z.object({ id: z.string() }))
    .parse(rows ?? [])
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, familyIds)
}
