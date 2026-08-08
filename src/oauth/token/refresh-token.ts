import type { Context } from "hono"
import { getSessionById } from "../../auth/session"
import {
  getRefreshTokenByFamilyId,
  getRefreshTokenByHash,
  type RefreshTokenRecord,
} from "../../db/queries/tokens"
import { getUserById } from "../../db/queries/users"
import { recordAudit } from "../../security/audit"
import { OAuthError } from "../../security/errors"
import { issueUserAccessToken } from "../../tokens/access-token"
import { issueIdToken } from "../../tokens/id-token"
import { rotateRefreshToken } from "../../tokens/refresh-token"
import { hashOpaqueToken } from "../../tokens/token-hash"
import type { AppBindings } from "../../types/app"
import type { OAuthClient } from "../../types/domain"
import { assertNever } from "../../utils/assert"
import { isExpired } from "../../utils/time"
import { consentCoversScopes } from "../consent"
import { resolveResourceForScopes } from "../resources"
import { parseScopeString } from "../scopes"
import { evaluateUserTokenAccess } from "../user-token-policy"
import type { TokenResponse } from "./response"

export async function handleRefreshToken(
  c: Context<AppBindings>,
  client: OAuthClient,
  form: URLSearchParams,
): Promise<Response> {
  const env = c.env
  const requestId = c.get("requestId")
  const presented = form.get("refresh_token")
  if (presented === null) {
    throw new OAuthError("invalid_request", {
      description: "Missing refresh_token",
      detail: "refresh_token grant without a refresh_token",
    })
  }
  if (!client.allowedGrantTypes.includes("refresh_token")) {
    throw new OAuthError("unauthorized_client", {
      description: "Client is not permitted to use this grant",
      detail: `refresh_token not allowed for ${client.clientId}`,
    })
  }

  // Bind the opaque token to its D1 family/client before entering the Durable
  // Object. When the hash is an already-rotated token, fall back to its family
  // prefix solely so the same legitimate client can still trigger reuse
  // detection; a different client is rejected before the DO is touched.
  const record = await lookupPresentedFamily(env, presented)
  if (
    record === null ||
    record.clientId !== client.clientId ||
    record.revokedAt !== null ||
    isExpired(record.expiresAt)
  ) {
    throw invalidRefreshToken(
      "refresh token unknown, expired, revoked, or belongs to another client",
    )
  }

  const originalScopes = parseScopeString(record.scope)
  const requestedScope = form.get("scope")
  const scopes = requestedScope === null ? originalScopes : parseScopeString(requestedScope)
  const originalScopeSet = new Set(originalScopes)
  if (scopes.length === 0 || scopes.some((scope) => !originalScopeSet.has(scope))) {
    throw new OAuthError("invalid_scope", {
      description: "Requested scope must be a non-empty subset of the original authorization",
      detail: "refresh scope expands or empties the original authorization",
    })
  }
  const effectiveScope = scopes.join(" ")
  const user = await getUserById(env, record.userId)
  if (user === null || user.disabled) {
    throw invalidRefreshToken(`user ${record.userId} missing or disabled`)
  }
  if (record.sessionId !== null) {
    const sourceSession = await getSessionById(env, record.sessionId)
    if (sourceSession === null || sourceSession.userId !== user.id) {
      throw invalidRefreshToken("source session was revoked, expired, or changed owner")
    }
  }
  const access = await evaluateUserTokenAccess(env, {
    userId: user.id,
    clientId: client.clientId,
    resourceUri: record.resource,
    scopes,
  })
  if (!access.allowed) {
    throw new OAuthError("invalid_grant", {
      description: "This account is not permitted to access this application or resource.",
      detail: `user token policy denied ${access.reason}`,
    })
  }
  if (!(await consentCoversScopes(env, user.id, client.clientId, record.resource, scopes))) {
    throw invalidRefreshToken("current consent no longer covers the refresh authorization")
  }
  try {
    await resolveResourceForScopes(env, client, record.resource, scopes)
  } catch (error) {
    if (error instanceof OAuthError) {
      throw invalidRefreshToken(
        `refresh authorization no longer permitted: ${error.detail ?? error.code}`,
      )
    }
    throw error
  }

  const outcome = await rotateRefreshToken(env, presented, client.clientId, effectiveScope)
  switch (outcome.status) {
    case "invalid":
      throw invalidRefreshToken("refresh token unknown, expired, revoked, or lost a rotation race")
    case "reuse_detected":
      await recordAudit(env, {
        type: "oauth.refresh.reused",
        clientId: client.clientId,
        requestId,
        success: false,
        detail: `refresh token reuse detected; family ${outcome.familyId} revoked`,
      })
      throw new OAuthError("invalid_grant", {
        description: "Invalid refresh token",
        detail: "refresh token reuse detected; token family revoked",
      })
    case "too_soon":
      return c.json(
        {
          error: "temporarily_unavailable",
          error_description: "Refresh token was rotated too recently; retry later",
        },
        429,
        {
          "cache-control": "no-store",
          pragma: "no-cache",
          "retry-after": String(outcome.retryAfterSeconds),
        },
      )
    case "reauthorization_required":
      throw new OAuthError("invalid_grant", {
        description: "Refresh token lifetime exhausted; authorize again",
        detail: `refresh family ${outcome.familyId} reached its generation limit and was revoked`,
      })
    case "rotated":
      return issueRotatedTokens(c, client, outcome)
    default:
      return assertNever(outcome)
  }
}

async function issueRotatedTokens(
  c: Context<AppBindings>,
  client: OAuthClient,
  outcome: {
    readonly token: string
    readonly userId: string
    readonly clientId: string
    readonly resource: string
    readonly scope: string
    readonly authTime: number
  },
): Promise<Response> {
  const env = c.env
  if (outcome.clientId !== client.clientId) {
    throw new OAuthError("invalid_grant", {
      description: "Invalid refresh token",
      detail: `refresh token family belongs to ${outcome.clientId}, presented by ${client.clientId}`,
    })
  }
  const user = await getUserById(env, outcome.userId)
  if (user === null || user.disabled) {
    throw new OAuthError("invalid_grant", {
      description: "The account is unavailable",
      detail: `user ${outcome.userId} missing or disabled`,
    })
  }
  const scopes = parseScopeString(outcome.scope)
  const accessToken = await issueUserAccessToken(env, {
    userId: user.id,
    clientId: client.clientId,
    resource: outcome.resource,
    scope: outcome.scope,
    authTime: outcome.authTime,
  })
  const response: TokenResponse = {
    access_token: accessToken.token,
    token_type: "Bearer",
    expires_in: accessToken.expiresIn,
    scope: outcome.scope,
    refresh_token: outcome.token,
  }
  if (scopes.includes("openid")) {
    response.id_token = await issueIdToken(env, {
      user,
      clientId: client.clientId,
      scopes,
      authTime: outcome.authTime,
      nonce: null,
    })
  }
  await recordAudit(env, {
    type: "oauth.refresh.used",
    userId: user.id,
    clientId: client.clientId,
    resourceUri: outcome.resource,
    scope: outcome.scope,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.json(response, 200, { "cache-control": "no-store", pragma: "no-cache" })
}

async function lookupPresentedFamily(
  env: Env,
  presentedToken: string,
): Promise<RefreshTokenRecord | null> {
  const byHash = await getRefreshTokenByHash(env, await hashOpaqueToken(presentedToken))
  if (byHash !== null) {
    return byHash
  }
  const separator = presentedToken.indexOf(".")
  if (separator <= 0) {
    return null
  }
  return getRefreshTokenByFamilyId(env, presentedToken.slice(0, separator))
}

function invalidRefreshToken(detail: string): OAuthError {
  return new OAuthError("invalid_grant", {
    description: "Invalid refresh token",
    detail,
  })
}
