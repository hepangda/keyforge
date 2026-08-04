import type { Context } from "hono"
import { getClientById } from "../db/queries/clients"
import { getUserById, getUserGroupNames } from "../db/queries/users"
import { buildUserClaims } from "../oidc/claims"
import { isPlausibleCompactJwt } from "../security/ingress"
import { verifyAccessToken } from "../tokens/jwt"
import type { AppBindings } from "../types/app"
import { extractBearerToken } from "./bearer"
import { consentCoversScopes } from "./consent"
import { resolveResourceForScopes } from "./resources"
import { parseScopeString } from "./scopes"
import { userMayReceiveScopes } from "./user-scope-policy"

function invalidToken(c: Context<AppBindings>, description: string): Response {
  c.header("www-authenticate", `Bearer error="invalid_token", error_description="${description}"`)
  return c.json({ error: "invalid_token", error_description: description }, 401)
}

export async function handleUserInfo(c: Context<AppBindings>): Promise<Response> {
  const token = extractBearerToken(c)
  if (token === null) {
    return invalidToken(c, "A bearer access token is required")
  }
  if (!isPlausibleCompactJwt(token)) {
    return invalidToken(c, "The access token is invalid or expired")
  }

  const payload = await verifyUserToken(c, token)
  if (payload === null) {
    return invalidToken(c, "The access token is invalid or expired")
  }
  const sub = payload.sub
  if (typeof sub !== "string" || sub.startsWith("client:") || payload["actor_type"] === "service") {
    return c.json({ error: "invalid_token", error_description: "Not a user token" }, 403)
  }

  const rawScope = payload["scope"]
  const scopes = parseScopeString(typeof rawScope === "string" ? rawScope : "")
  if (!scopes.includes("openid") || !(await audienceIsCurrent(c, payload))) {
    return invalidToken(c, "The access token is not valid for UserInfo")
  }

  const user = await getUserById(c.env, sub)
  if (user === null || user.disabled) {
    return invalidToken(c, "The subject is unavailable")
  }
  if (!(await userMayReceiveScopes(c.env, user.id, scopes))) {
    return invalidToken(c, "The subject is no longer permitted to use this token")
  }
  const groups = await getUserGroupNames(c.env, user.id)
  return c.json({ sub: user.id, ...buildUserClaims(c.env, user, groups, scopes) }, 200, {
    "cache-control": "no-store",
  })
}

async function verifyUserToken(
  c: Context<AppBindings>,
  token: string,
): Promise<Awaited<ReturnType<typeof verifyAccessToken>> | null> {
  try {
    return await verifyAccessToken(c.env, token)
  } catch (error) {
    if (error instanceof Error) {
      return null
    }
    throw error
  }
}

async function audienceIsCurrent(
  c: Context<AppBindings>,
  payload: Awaited<ReturnType<typeof verifyAccessToken>>,
): Promise<boolean> {
  if (typeof payload.aud !== "string" || typeof payload["client_id"] !== "string") {
    return false
  }
  const client = await getClientById(c.env, payload["client_id"])
  if (client === null || !client.enabled) {
    return false
  }
  try {
    await resolveResourceForScopes(
      c.env,
      client,
      payload.aud,
      parseScopeString(typeof payload["scope"] === "string" ? payload["scope"] : ""),
    )
    if (typeof payload.sub !== "string") return false
    return consentCoversScopes(
      c.env,
      payload.sub,
      client.clientId,
      payload.aud,
      parseScopeString(typeof payload["scope"] === "string" ? payload["scope"] : ""),
    )
  } catch (error) {
    if (error instanceof Error) {
      return false
    }
    throw error
  }
}
