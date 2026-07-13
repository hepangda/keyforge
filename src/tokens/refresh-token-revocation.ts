import { z } from "zod"
import { nowSeconds } from "../utils/time"

const familyIdRowSchema = z.object({ id: z.string() })

/**
 * D1 is the immediate revocation authority. Mirror the committed state into
 * the per-family Durable Objects with a bounded retry, but never turn a
 * successful D1 security transition into a failed user response.
 */
export async function revokeRefreshFamilyDurableObjects(
  env: Env,
  familyIds: readonly string[],
): Promise<void> {
  let pending = [...new Set(familyIds)]
  for (let attempt = 0; attempt < 2 && pending.length > 0; attempt += 1) {
    const results = await Promise.allSettled(
      pending.map((familyId) => env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke()),
    )
    pending = pending.filter((_, index) => results[index]?.status === "rejected")
  }
  if (pending.length > 0) {
    console.error("refresh_family.do_revocation_failed", pending)
  }
}

async function revokeMatchingFamilies(
  env: Env,
  sql: string,
  bindings: readonly unknown[],
): Promise<number> {
  // UPDATE ... RETURNING makes the D1 mirror authoritative immediately and
  // gives us the exact set of Durable Objects that must also be burned.
  const result = await env.DB.prepare(sql)
    .bind(nowSeconds(), ...bindings)
    .all()
  const familyIds = z
    .array(familyIdRowSchema)
    .parse(result.results)
    .map((row) => row.id)
  await revokeRefreshFamilyDurableObjects(env, familyIds)
  return familyIds.length
}

/** Revoke every refresh family belonging to one user/client authorization. */
export function revokeRefreshFamiliesByUserClient(
  env: Env,
  userId: string,
  clientId: string,
): Promise<number> {
  return revokeMatchingFamilies(
    env,
    `UPDATE refresh_tokens SET revoked_at = ?
     WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL
     RETURNING id`,
    [userId, clientId],
  )
}

/** Revoke refresh families created from one browser/session authentication. */
export function revokeRefreshFamiliesBySessionId(env: Env, sessionId: string): Promise<number> {
  return revokeMatchingFamilies(
    env,
    `UPDATE refresh_tokens SET revoked_at = ?
     WHERE session_id = ? AND revoked_at IS NULL
     RETURNING id`,
    [sessionId],
  )
}

/** Revoke every refresh family for a user, including device-authorized families. */
export function revokeRefreshFamiliesForUser(env: Env, userId: string): Promise<number> {
  return revokeMatchingFamilies(
    env,
    `UPDATE refresh_tokens SET revoked_at = ?
     WHERE user_id = ? AND revoked_at IS NULL
     RETURNING id`,
    [userId],
  )
}

/** Revoke every family except those attached to the browser session being kept. */
export function revokeRefreshFamiliesForOtherUserSessions(
  env: Env,
  userId: string,
  keepSessionId: string,
): Promise<number> {
  return revokeMatchingFamilies(
    env,
    `UPDATE refresh_tokens SET revoked_at = ?
     WHERE user_id = ? AND (session_id IS NULL OR session_id != ?) AND revoked_at IS NULL
     RETURNING id`,
    [userId, keepSessionId],
  )
}
