import type { Context } from "hono"
import { USER_ONLY_SCOPES } from "../config"
import { recordAudit } from "../security/audit"
import { OAuthError } from "../security/errors"
import { issueServiceAccessToken } from "../tokens/access-token"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"
import { resolveResourceForScopes } from "./resources"
import { parseScopeString, serializeScopes, validateRequestedScopes } from "./scopes"

const userOnlyScopeSet = new Set<string>(USER_ONLY_SCOPES)

/**
 * client_credentials grant. Confidential clients only; user-context scopes
 * (openid/profile/email/offline_access) are rejected; no id_token or
 * refresh_token is issued — only a service access token bound to a resource.
 */
export async function handleClientCredentials(
  c: Context<AppBindings>,
  client: OAuthClient,
  form: URLSearchParams,
): Promise<Response> {
  const env = c.env
  const requestId = c.get("requestId")

  if (client.type !== "confidential") {
    await denied(env, client.clientId, requestId, "public client cannot use client_credentials")
    throw new OAuthError("unauthorized_client", {
      description: "Client is not permitted to use this grant",
      detail: `client ${client.clientId} is public`,
    })
  }
  if (!client.allowedGrantTypes.includes("client_credentials")) {
    await denied(env, client.clientId, requestId, "grant not in client allowed_grant_types")
    throw new OAuthError("unauthorized_client", {
      description: "Client is not permitted to use this grant",
      detail: `client_credentials not allowed for ${client.clientId}`,
    })
  }

  const requestedScopes = parseScopeString(form.get("scope"))
  const forbidden = requestedScopes.filter((scope) => userOnlyScopeSet.has(scope))
  if (forbidden.length > 0) {
    await denied(
      env,
      client.clientId,
      requestId,
      `user-only scopes requested: ${forbidden.join(" ")}`,
    )
    throw new OAuthError("invalid_scope", {
      description: "Requested scope is not available to service clients",
      detail: `user-only scopes rejected: ${forbidden.join(" ")}`,
    })
  }

  const effectiveScopes =
    requestedScopes.length > 0
      ? requestedScopes
      : client.allowedScopes.filter((scope) => !userOnlyScopeSet.has(scope))
  const grantedScopes = validateRequestedScopes(effectiveScopes, client.allowedScopes)
  const resource = await resolveResourceForScopes(env, client, form.get("resource"), grantedScopes)
  const scope = serializeScopes(grantedScopes)

  const issued = await issueServiceAccessToken(env, { clientId: client.clientId, resource, scope })
  await recordAudit(env, {
    type: "oauth.client_credentials.issued",
    actorClientId: client.clientId,
    clientId: client.clientId,
    resourceUri: resource,
    scope,
    requestId,
    success: true,
  })

  return c.json(
    { access_token: issued.token, token_type: "Bearer", expires_in: issued.expiresIn, scope },
    200,
    { "cache-control": "no-store", pragma: "no-cache" },
  )
}

function denied(env: Env, clientId: string, requestId: string, detail: string): Promise<void> {
  return recordAudit(env, {
    type: "oauth.client_credentials.denied",
    clientId,
    requestId,
    success: false,
    detail,
  })
}
