import type { Context } from "hono"
import { getClientById } from "../db/queries/clients"
import { getUserById } from "../db/queries/users"
import { buildUserClaims } from "../oidc/claims"
import { isPlausibleCompactJwt } from "../security/ingress"
import { verifyAccessToken } from "../tokens/jwt"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"
import { extractBearerToken } from "./bearer"
import { consentCoversScopes } from "./consent"
import { resolveResourceForScopes } from "./resources"
import { parseScopeString } from "./scopes"
import { evaluateUserTokenAccess } from "./user-token-policy"

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
  if (scopes.includes("groups")) {
    return invalidToken(c, "The access token is not valid for UserInfo")
  }
  if (!scopes.includes("openid")) {
    return invalidToken(c, "The access token is not valid for UserInfo")
  }
  const tokenClient = await currentAudienceClient(c, payload)
  if (tokenClient === null || typeof payload.aud !== "string") {
    return invalidToken(c, "The access token is not valid for UserInfo")
  }

  const user = await getUserById(c.env, sub)
  if (user === null || user.disabled) {
    return invalidToken(c, "The subject is unavailable")
  }
  const access = await evaluateUserTokenAccess(c.env, {
    userId: user.id,
    clientId: tokenClient.clientId,
    resourceUri: payload.aud,
    scopes,
  })
  if (!access.allowed) {
    return invalidToken(c, "The subject is no longer permitted to use this token")
  }
  return c.json({ sub: user.id, ...buildUserClaims(c.env, user, scopes) }, 200, {
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

async function currentAudienceClient(
  c: Context<AppBindings>,
  payload: Awaited<ReturnType<typeof verifyAccessToken>>,
): Promise<OAuthClient | null> {
  if (typeof payload.aud !== "string" || typeof payload["client_id"] !== "string") {
    return null
  }
  const client = await getClientById(c.env, payload["client_id"])
  if (client === null || !client.enabled) {
    return null
  }
  try {
    await resolveResourceForScopes(
      c.env,
      client,
      payload.aud,
      parseScopeString(typeof payload["scope"] === "string" ? payload["scope"] : ""),
    )
    if (typeof payload.sub !== "string") return null
    return (await consentCoversScopes(
      c.env,
      payload.sub,
      client.clientId,
      payload.aud,
      parseScopeString(typeof payload["scope"] === "string" ? payload["scope"] : ""),
    ))
      ? client
      : null
  } catch (error) {
    if (error instanceof Error) {
      return null
    }
    throw error
  }
}
