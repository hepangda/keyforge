import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"

export type AuthorizationGrantInput = {
  readonly userId: string
  readonly clientId: string
  readonly sessionId: string | null
  readonly scope: string
  readonly resource: string
  readonly grantType: string
}

export async function recordAuthorizationGrant(
  env: Env,
  input: AuthorizationGrantInput,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO authorization_grants
       (id, user_id, client_id, session_id, scope, resource, grant_type, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      generateId(ID_PREFIX.authGrant),
      input.userId,
      input.clientId,
      input.sessionId,
      input.scope,
      input.resource,
      input.grantType,
      nowSeconds(),
    )
    .run()
}

/** Revoke all historical grants represented by one user/client authorization. */
export async function revokeAuthorizationGrantsByUserClient(
  env: Env,
  userId: string,
  clientId: string,
): Promise<number> {
  const result = await env.DB.prepare(
    `UPDATE authorization_grants SET revoked_at = ?
     WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL`,
  )
    .bind(nowSeconds(), userId, clientId)
    .run()
  return result.meta.changes
}
