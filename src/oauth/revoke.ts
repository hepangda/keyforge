import type { Context } from "hono"
import {
  getRefreshTokenByFamilyId,
  getRefreshTokenByHash,
  markRefreshTokenRevoked,
} from "../db/queries/tokens"
import { recordAudit } from "../security/audit"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"

/**
 * RFC 7009 revocation. Only opaque refresh tokens are server-side revocable
 * (access tokens are stateless JWTs). Per the RFC, the response is 200 even for
 * an unknown token so callers cannot probe token validity.
 */
export async function handleRevoke(
  c: Context<AppBindings>,
  client: OAuthClient,
  form: URLSearchParams,
): Promise<Response> {
  const token = form.get("token")
  if (token === null) {
    return c.json({ error: "invalid_request", error_description: "Missing token" }, 400)
  }

  let record = await getRefreshTokenByHash(c.env, await hashOpaqueToken(token))
  if (record === null) {
    const separator = token.indexOf(".")
    if (separator > 0) record = await getRefreshTokenByFamilyId(c.env, token.slice(0, separator))
  }
  if (record !== null && record.clientId === client.clientId) {
    await c.env.REFRESH_TOKEN_FAMILY.getByName(record.familyId).revoke()
    await markRefreshTokenRevoked(c.env, record.familyId)
    await recordAudit(c.env, {
      type: "oauth.token.revoked",
      userId: record.userId,
      clientId: client.clientId,
      requestId: c.get("requestId"),
      success: true,
    })
  }
  return c.body(null, 200, { "cache-control": "no-store" })
}
