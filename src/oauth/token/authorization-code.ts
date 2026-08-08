import type { Context } from "hono"
import { getSessionById } from "../../auth/session"
import { recordAuthorizationGrant } from "../../db/queries/grants"
import { getUserById } from "../../db/queries/users"
import { recordAudit } from "../../security/audit"
import { OAuthError } from "../../security/errors"
import { hashOpaqueToken } from "../../tokens/token-hash"
import type { AppBindings } from "../../types/app"
import type { OAuthClient } from "../../types/domain"
import { consentCoversScopes } from "../consent"
import { resolveResourceForScopes } from "../resources"
import { parseScopeString } from "../scopes"
import { evaluateUserTokenAccess } from "../user-token-policy"
import { issueUserTokens } from "./issue"

export async function handleAuthorizationCode(
  c: Context<AppBindings>,
  client: OAuthClient,
  form: URLSearchParams,
): Promise<Response> {
  const env = c.env
  const requestId = c.get("requestId")
  const code = form.get("code")
  const redirectUri = form.get("redirect_uri")
  const codeVerifier = form.get("code_verifier")
  if (code === null || redirectUri === null || codeVerifier === null) {
    throw new OAuthError("invalid_request", {
      description: "Missing code, redirect_uri, or code_verifier",
      detail: "authorization_code request missing a required parameter",
    })
  }

  const consumed = await env.AUTHORIZATION_CODE.getByName(await hashOpaqueToken(code)).consumeIf({
    clientId: client.clientId,
    redirectUri,
    codeVerifier,
  })
  if (!consumed.found) {
    if (consumed.reason === "pkce") {
      await recordAudit(env, {
        type: "security.invalid_pkce",
        clientId: client.clientId,
        requestId,
        success: false,
        detail: "code_verifier did not match code_challenge",
      })
    }
    throw new OAuthError("invalid_grant", {
      description: "Invalid or expired authorization code",
      detail: `authorization code validation failed: ${consumed.reason}`,
    })
  }
  const grant = consumed.value

  const user = await getUserById(env, grant.userId)
  if (user === null || user.disabled) {
    throw new OAuthError("invalid_grant", {
      description: "The account is unavailable",
      detail: `user ${grant.userId} missing or disabled`,
    })
  }

  const scopes = parseScopeString(grant.scope)
  const sourceSession = await getSessionById(env, grant.sessionId)
  if (sourceSession === null || sourceSession.userId !== user.id) {
    throw new OAuthError("invalid_grant", {
      description: "The authorization session is no longer active",
      detail: `session ${grant.sessionId} was revoked, expired, or changed owner`,
    })
  }
  if (!(await consentCoversScopes(env, user.id, client.clientId, grant.resource, scopes))) {
    throw new OAuthError("invalid_grant", {
      description: "The authorization was revoked",
      detail: "consent no longer covers the authorization code grant",
    })
  }
  const access = await evaluateUserTokenAccess(env, {
    userId: user.id,
    clientId: client.clientId,
    resourceUri: grant.resource,
    scopes,
  })
  if (!access.allowed) {
    throw new OAuthError("invalid_grant", {
      description: "This account is not permitted to access this application or resource.",
      detail: `user token policy denied ${access.reason}`,
    })
  }

  await resolveResourceForScopes(env, client, grant.resource, scopes)

  const response = await issueUserTokens(env, {
    user,
    client,
    scope: grant.scope,
    resource: grant.resource,
    nonce: grant.nonce,
    authTime: grant.authTime,
    sessionId: grant.sessionId,
  })

  await recordAuthorizationGrant(env, {
    userId: user.id,
    clientId: client.clientId,
    sessionId: grant.sessionId,
    scope: grant.scope,
    resource: grant.resource,
    grantType: "authorization_code",
  })
  await recordAudit(env, {
    type: "oauth.token.issued",
    userId: user.id,
    clientId: client.clientId,
    resourceUri: grant.resource,
    scope: grant.scope,
    requestId,
    success: true,
  })
  return c.json(response, 200, { "cache-control": "no-store", pragma: "no-cache" })
}
