import type { Context } from "hono"
import { getSessionById } from "../auth/session"
import { getClientById } from "../db/queries/clients"
import { getRefreshTokenByHash } from "../db/queries/tokens"
import { getUserById } from "../db/queries/users"
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

export async function handleIntrospect(
  c: Context<AppBindings>,
  form: URLSearchParams,
  introspector: OAuthClient,
): Promise<Response> {
  const token = form.get("token")
  if (token === null) {
    return c.json({ error: "invalid_request", error_description: "Missing token" }, 400)
  }

  const jwtResult = await introspectAccessToken(c, token, introspector)
  if (jwtResult !== null) {
    return c.json(jwtResult, 200, { "cache-control": "no-store" })
  }

  const record = await getRefreshTokenByHash(c.env, await hashOpaqueToken(token))
  if (record === null || record.revokedAt !== null || isExpired(record.expiresAt)) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  const familyState = await c.env.REFRESH_TOKEN_FAMILY.getByName(record.familyId).getState()
  if (familyState === null || familyState.revoked) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  if (!mayInspectClientTokens(introspector, record.clientId)) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  if (!introspector.allowedResources.includes(record.resource)) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  const [tokenClient, user] = await Promise.all([
    getClientById(c.env, record.clientId),
    getUserById(c.env, record.userId),
  ])
  const scopes = parseScopeString(record.scope)
  if (scopes.includes("groups")) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  if (tokenClient === null || !tokenClient.enabled || user === null || user.disabled) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  const access = await evaluateUserTokenAccess(c.env, {
    userId: user.id,
    clientId: tokenClient.clientId,
    resourceUri: record.resource,
    scopes,
  })
  if (!access.allowed) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  if (!(await consentCoversScopes(c.env, user.id, tokenClient.clientId, record.resource, scopes))) {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  if (record.sessionId !== null) {
    const sourceSession = await getSessionById(c.env, record.sessionId)
    if (sourceSession === null || sourceSession.userId !== user.id) {
      return c.json(INACTIVE, 200, { "cache-control": "no-store" })
    }
  }
  try {
    await resolveResourceForScopes(c.env, tokenClient, record.resource, scopes)
  } catch {
    return c.json(INACTIVE, 200, { "cache-control": "no-store" })
  }
  return c.json(
    {
      active: true,
      sub: record.userId,
      client_id: record.clientId,
      scope: record.scope,
      aud: record.resource,
      exp: record.expiresAt,
      token_type: "refresh_token",
    },
    200,
    { "cache-control": "no-store" },
  )
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
      if (!(await consentCoversScopes(c.env, user.id, tokenClient.clientId, payload.aud, scopes))) {
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
