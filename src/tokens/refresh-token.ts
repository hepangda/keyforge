import { REFRESH_TOKEN_POLICY, TOKEN_TTL } from "../config"
import { markRefreshTokenRevoked } from "../db/queries/tokens"
import type { RotateResult } from "../do/RefreshTokenFamilyDO"
import { OAuthError } from "../security/errors"
import { assertNever } from "../utils/assert"
import { generateId, ID_PREFIX } from "../utils/id"
import { randomToken } from "../utils/random"
import { nowSeconds } from "../utils/time"
import { revokeRefreshFamilyDurableObjects } from "./refresh-token-revocation"
import { hashOpaqueToken } from "./token-hash"

export type IssueRefreshInput = {
  readonly userId: string
  readonly clientId: string
  readonly sessionId: string | null
  readonly resource: string
  readonly scope: string
  readonly authTime: number
  readonly rememberMe: boolean
}

export type IssuedRefreshToken = {
  readonly token: string
  readonly familyId: string
  readonly expiresAt: number
}

export async function issueRefreshToken(
  env: Env,
  input: IssueRefreshInput,
): Promise<IssuedRefreshToken> {
  const familyId = generateId(ID_PREFIX.refreshTokenFamily)
  const token = `${familyId}.${randomToken(32)}`
  const tokenHash = await hashOpaqueToken(token)
  const now = nowSeconds()
  const ttl = input.rememberMe ? TOKEN_TTL.refreshTokenRememberMe : TOKEN_TTL.refreshToken
  const expiresAt = now + ttl

  await env.REFRESH_TOKEN_FAMILY.getByName(familyId).init({
    userId: input.userId,
    clientId: input.clientId,
    resource: input.resource,
    scope: input.scope,
    authTime: input.authTime,
    currentTokenHash: tokenHash,
    absoluteExpiresAt: expiresAt,
  })
  const sessionGuard =
    input.sessionId === null
      ? `EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.disabled = 0)`
      : `EXISTS (
          SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.id = ? AND s.user_id = ? AND s.revoked_at IS NULL
            AND s.expires_at > ? AND u.disabled = 0
        )`
  const guardBindings =
    input.sessionId === null ? [input.userId] : [input.sessionId, input.userId, now]
  const insertStatement = env.DB.prepare(
    `INSERT INTO refresh_tokens
       (id, token_hash, user_id, client_id, session_id, resource, scope, generation,
        remember_me, created_at, last_rotated_at, expires_at, auth_time)
     SELECT ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?
     WHERE ${sessionGuard}`,
  ).bind(
    familyId,
    tokenHash,
    input.userId,
    input.clientId,
    input.sessionId,
    input.resource,
    input.scope,
    input.rememberMe ? 1 : 0,
    now,
    now,
    expiresAt,
    input.authTime,
    ...guardBindings,
  )
  // Keep the newly-issued family and deterministically revoke the oldest
  // excess families. D1 batch is one transaction, so concurrent issuances
  // cannot leave the user/client pair above the hard active-family cap.
  const pruneStatement = env.DB.prepare(
    `UPDATE refresh_tokens SET revoked_at = ?
     WHERE id IN (
       SELECT candidate.id
       FROM refresh_tokens candidate
       WHERE candidate.user_id = ? AND candidate.client_id = ?
         AND candidate.revoked_at IS NULL AND candidate.expires_at > ?
         AND candidate.id != ?
       ORDER BY candidate.created_at ASC, candidate.id ASC
       LIMIT (
         SELECT max(count(*) - ?, 0)
         FROM refresh_tokens active
         WHERE active.user_id = ? AND active.client_id = ?
           AND active.revoked_at IS NULL AND active.expires_at > ?
       )
     )
       AND EXISTS (
         SELECT 1 FROM refresh_tokens issued
         WHERE issued.id = ? AND issued.revoked_at IS NULL
       )
     RETURNING id`,
  ).bind(
    now,
    input.userId,
    input.clientId,
    now,
    familyId,
    REFRESH_TOKEN_POLICY.maximumActiveFamiliesPerUserClient,
    input.userId,
    input.clientId,
    now,
    familyId,
  )
  let inserted: D1Result
  let pruned: D1Result<{ id: string }>
  try {
    ;[inserted, pruned] = (await env.DB.batch([insertStatement, pruneStatement])) as [
      D1Result,
      D1Result<{ id: string }>,
    ]
  } catch (error) {
    await env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke()
    throw error
  }
  if (inserted.meta.changes !== 1) {
    await env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke()
    throw new OAuthError("invalid_grant", {
      description: "The authorization session is no longer active",
      detail: "session or user changed while creating the refresh token family",
    })
  }
  const prunedFamilyIds = pruned.results.flatMap((row) =>
    typeof row.id === "string" ? [row.id] : [],
  )
  await revokeRefreshFamilyDurableObjects(env, prunedFamilyIds)
  return { token, familyId, expiresAt }
}

export type RotateOutcome =
  | {
      readonly status: "rotated"
      readonly token: string
      readonly userId: string
      readonly clientId: string
      readonly resource: string
      readonly scope: string
      readonly authTime: number
    }
  | { readonly status: "reuse_detected"; readonly familyId: string }
  | { readonly status: "too_soon"; readonly retryAfterSeconds: number }
  | { readonly status: "reauthorization_required"; readonly familyId: string }
  | { readonly status: "invalid" }

export async function rotateRefreshToken(
  env: Env,
  presentedToken: string,
  expectedClientId: string,
  nextScope: string,
): Promise<RotateOutcome> {
  const familyId = presentedToken.split(".")[0] ?? ""
  const presentedHash = await hashOpaqueToken(presentedToken)
  const newToken = `${familyId}.${randomToken(32)}`
  const newHash = await hashOpaqueToken(newToken)
  const result: RotateResult = await env.REFRESH_TOKEN_FAMILY.getByName(familyId).rotate(
    presentedHash,
    newHash,
    expectedClientId,
    nextScope,
  )

  switch (result.status) {
    case "rotated": {
      let updated: D1Result
      try {
        updated = await env.DB.prepare(
          `UPDATE refresh_tokens SET token_hash = ?, scope = ?, generation = ?, last_rotated_at = ?
           WHERE id = ? AND revoked_at IS NULL`,
        )
          .bind(newHash, result.meta.scope, result.meta.generation, nowSeconds(), familyId)
          .run()
      } catch (error) {
        // The DO has already advanced. Fail closed so neither old nor a
        // partially-mirrored new token can be used after a D1 outage.
        await env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke()
        throw error
      }
      // A concurrent session/app revocation marks D1 first. If it won that
      // race, burn the just-rotated DO state and never return fresh tokens.
      if (updated.meta.changes !== 1) {
        await env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke()
        return { status: "invalid" }
      }
      return {
        status: "rotated",
        token: newToken,
        userId: result.meta.userId,
        clientId: result.meta.clientId,
        resource: result.meta.resource,
        scope: result.meta.scope,
        authTime: result.meta.authTime ?? result.meta.createdAt,
      }
    }
    case "reuse_detected":
      await env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?")
        .bind(nowSeconds(), familyId)
        .run()
      return { status: "reuse_detected", familyId }
    case "too_soon":
      return { status: "too_soon", retryAfterSeconds: result.retryAfterSeconds }
    case "generation_limit":
      await markRefreshTokenRevoked(env, familyId)
      return { status: "reauthorization_required", familyId }
    case "revoked":
    case "expired":
    case "invalid":
      return { status: "invalid" }
    default:
      return assertNever(result)
  }
}
