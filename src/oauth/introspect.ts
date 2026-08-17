import type { Context } from "hono"
import { getSessionById } from "../auth/session"
import { getClientById } from "../db/queries/clients"
import { getRefreshTokenByHash } from "../db/queries/tokens"
import { getUserById } from "../db/queries/users"
import { recordAudit } from "../security/audit"
import { verifyAccessToken } from "../tokens/jwt"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"
import { isExpired } from "../utils/time"
import { consentCoversScopes } from "./consent"
import { resolveResourceForScopes } from "./resources"
import { parseScopeString } from "./scopes"
import { evaluateUserTokenAccess } from "./user-token-policy"

const INACTIVE = { active: false } as const

async function introspectionResponse(
  c: Context<AppBindings>,
  introspector: OAuthClient,
  result: Readonly<Record<string, unknown>>,
  status: 200 | 400 = 200,
  target: { readonly clientId?: string; readonly resourceUri?: string } = {},
): Promise<Response> {
  const active = result["active"] === true
  const clientId = typeof result["client_id"] === "string" ? result["client_id"] : target.clientId
  const resourceUri = typeof result["aud"] === "string" ? result["aud"] : target.resourceUri
  await recordAudit(c.env, {
    type: "oauth.introspection.completed",
    actorClientId: introspector.clientId,
    clientId: clientId ?? null,
    resourceUri: resourceUri ?? null,
    requestId: c.get("requestId"),
    success: active,
    detail: active
      ? "token active"
      : status === 400
        ? "invalid introspection request"
        : "token inactive",
    metadata: { active },
  })
  return c.json(result, status, { "cache-control": "no-store" })
}

export async function handleIntrospect(
  c: Context<AppBindings>,
  form: URLSearchParams,
  introspector: OAuthClient,
): Promise<Response> {
  const token = form.get("token")
  if (token === null) {
    return introspectionResponse(
      c,
      introspector,
      { error: "invalid_request", error_description: "Missing token" },
      400,
    )
  }

  const jwtResult = await introspectAccessToken(c, token, introspector)
  if (jwtResult !== null) {
    return introspectionResponse(c, introspector, jwtResult)
  }

  const record = await getRefreshTokenByHash(c.env, await hashOpaqueToken(token))
  if (record === null) {
    return introspectionResponse(c, introspector, INACTIVE)
  }
  const target = { clientId: record.clientId, resourceUri: record.resource }
  if (record.revokedAt !== null || isExpired(record.expiresAt)) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  const familyState = await c.env.REFRESH_TOKEN_FAMILY.getByName(record.familyId).getState()
  if (familyState === null || familyState.revoked) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  if (!mayInspectClientTokens(introspector, record.clientId)) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  if (!introspector.allowedResources.includes(record.resource)) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  const [tokenClient, user] = await Promise.all([
    getClientById(c.env, record.clientId),
    getUserById(c.env, record.userId),
  ])
  const scopes = parseScopeString(record.scope)
  if (scopes.includes("groups")) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  if (tokenClient === null || !tokenClient.enabled || user === null || user.disabled) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  const access = await evaluateUserTokenAccess(c.env, {
    userId: user.id,
    clientId: tokenClient.clientId,
    resourceUri: record.resource,
    scopes,
  })
  if (!access.allowed) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  if (
    !(await consentCoversScopes(
      c.env,
      user.id,
      tokenClient.clientId,
      record.resource,
      scopes,
      tokenClient.metadataFingerprint,
    ))
  ) {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  if (record.sessionId !== null) {
    const sourceSession = await getSessionById(c.env, record.sessionId)
    if (sourceSession === null || sourceSession.userId !== user.id) {
      return introspectionResponse(c, introspector, INACTIVE, 200, target)
    }
  }
  try {
    await resolveResourceForScopes(c.env, tokenClient, record.resource, scopes)
  } catch {
    return introspectionResponse(c, introspector, INACTIVE, 200, target)
  }
  return introspectionResponse(c, introspector, {
    active: true,
    sub: record.userId,
    client_id: record.clientId,
    scope: record.scope,
    aud: record.resource,
    exp: record.expiresAt,
    token_type: "refresh_token",
  })
}

async function introspectAccessToken(
  c: Context<AppBindings>,
  token: string,
  introspector: OAuthClient,
): Promise<Record<string, unknown> | null> {
  try {
    if (introspector.allowedResources.length === 0) {
      return null
    }
    const payload = await verifyAccessToken(c.env, token, {
      audience: introspector.allowedResources,
    })
    if (typeof payload.aud !== "string" || typeof payload["client_id"] !== "string") {
      return null
    }
    if (!mayInspectClientTokens(introspector, payload["client_id"])) {
      return null
    }
    const tokenClient = await getClientById(c.env, payload["client_id"])
    if (tokenClient === null || !tokenClient.enabled) {
      return null
    }
    await resolveResourceForScopes(
      c.env,
      tokenClient,
      payload.aud,
      parseScopeString(typeof payload["scope"] === "string" ? payload["scope"] : ""),
    )
    const scopes = parseScopeString(typeof payload["scope"] === "string" ? payload["scope"] : "")
    if (scopes.includes("groups")) return null
    const isService = payload["actor_type"] === "service" || payload.sub?.startsWith("client:")
    if (!isService) {
      if (typeof payload.sub !== "string") return null
      const user = await getUserById(c.env, payload.sub)
      if (user === null || user.disabled) return null
      const access = await evaluateUserTokenAccess(c.env, {
        userId: user.id,
        clientId: tokenClient.clientId,
        resourceUri: payload.aud,
        scopes,
      })
      if (!access.allowed) return null
      if (
        !(await consentCoversScopes(
          c.env,
          user.id,
          tokenClient.clientId,
          payload.aud,
          scopes,
          tokenClient.metadataFingerprint,
        ))
      ) {
        return null
      }
    }
    return {
      active: true,
      sub: payload.sub,
      aud: payload.aud,
      iss: payload.iss,
      exp: payload.exp,
      iat: payload.iat,
      jti: payload["jti"],
      scope: payload["scope"],
      client_id: payload["client_id"],
      token_use: payload["token_use"],
      token_type: "Bearer",
    }
  } catch (error) {
    if (error instanceof Error) {
      return null
    }
    throw error
  }
}

/**
 * Resource services may inspect any token for an audience they protect.
 * Confidential web applications may inspect only tokens issued to themselves;
 * this lets an RP observe upstream session revocation without becoming a token
 * oracle for another client.
 */
function mayInspectClientTokens(introspector: OAuthClient, tokenClientId: string): boolean {
  return (
    introspector.clientKind === "service" ||
    (introspector.clientKind === "application" && introspector.clientId === tokenClientId)
  )
}
