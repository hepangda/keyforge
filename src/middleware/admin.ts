import type { Context } from "hono"
import { createMiddleware } from "hono/factory"
import { ADMIN_API } from "../config"
import { getClientById } from "../db/queries/clients"
import { getUserById } from "../db/queries/users"
import { extractBearerToken } from "../oauth/bearer"
import { resolveResourceForScopes } from "../oauth/resources"
import { parseScopeString } from "../oauth/scopes"
import { evaluateUserTokenAccess } from "../oauth/user-token-policy"
import { isYoloEnabled } from "../operations/yolo"
import { isPlausibleCompactJwt } from "../security/ingress"
import { RECENT_AUTH_SECONDS } from "../security/recent-auth"
import { verifyAccessToken } from "../tokens/jwt"
import type { AppBindings } from "../types/app"
import { nowSeconds } from "../utils/time"

const READ_METHODS = new Set(["GET", "HEAD"])
const BEARER_SCHEME = "Bearer"

function invalidToken(c: Context<AppBindings>): Response {
  c.header("www-authenticate", `${BEARER_SCHEME} realm="admin", error="invalid_token"`)
  return c.json({ error: "invalid_token" }, 401)
}

function insufficientScope(c: Context<AppBindings>, requiredScope: string): Response {
  c.header(
    "www-authenticate",
    `${BEARER_SCHEME} realm="admin", error="insufficient_scope", scope="${requiredScope}"`,
  )
  return c.json({ error: "insufficient_scope", required_scope: requiredScope }, 403)
}

function reauthenticationRequired(c: Context<AppBindings>): Response {
  return c.json({ error: "reauthentication_required" }, 403)
}

export const requireAdminApiToken = createMiddleware<AppBindings>(async (c, next) => {
  const sessionUser = c.get("user")
  if (sessionUser !== undefined && isYoloEnabled(c.env)) {
    await next()
    return
  }

  const token = extractBearerToken(c)
  if (token === null || !isPlausibleCompactJwt(token)) return invalidToken(c)

  let payload: Awaited<ReturnType<typeof verifyAccessToken>>
  try {
    payload = await verifyAccessToken(c.env, token, {
      audience: ADMIN_API.audience,
      actor: "user",
    })
  } catch (error) {
    if (error instanceof Error) return invalidToken(c)
    throw error
  }
  if (
    payload.aud !== ADMIN_API.audience ||
    typeof payload.sub !== "string" ||
    typeof payload["client_id"] !== "string"
  ) {
    return invalidToken(c)
  }

  const scopes = parseScopeString(
    typeof payload["scope"] === "string" ? payload["scope"] : undefined,
  )
  const requiredScope = READ_METHODS.has(c.req.method.toUpperCase())
    ? ADMIN_API.readScope
    : ADMIN_API.writeScope
  if (!scopes.includes(requiredScope)) return insufficientScope(c, requiredScope)
  const [user, client] = await Promise.all([
    getUserById(c.env, payload.sub),
    getClientById(c.env, payload["client_id"]),
  ])
  if (user === null || user.disabled || client === null || !client.enabled) {
    return invalidToken(c)
  }
  try {
    await resolveResourceForScopes(c.env, client, ADMIN_API.audience, scopes)
  } catch (error) {
    if (error instanceof Error) return invalidToken(c)
    throw error
  }
  const access = await evaluateUserTokenAccess(c.env, {
    userId: user.id,
    clientId: client.clientId,
    resourceUri: ADMIN_API.audience,
    scopes,
  })
  if (!access.allowed) return invalidToken(c)

  if (requiredScope === ADMIN_API.writeScope) {
    const authTime = payload["auth_time"]
    const now = nowSeconds()
    if (
      typeof authTime !== "number" ||
      !Number.isSafeInteger(authTime) ||
      authTime > now ||
      now - authTime > RECENT_AUTH_SECONDS
    ) {
      return reauthenticationRequired(c)
    }
  }

  c.set("user", user)
  await next()
})
