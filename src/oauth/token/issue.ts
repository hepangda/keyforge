import { OAuthError } from "../../security/errors"
import { issueUserAccessToken } from "../../tokens/access-token"
import { issueIdToken } from "../../tokens/id-token"
import { issueRefreshToken } from "../../tokens/refresh-token"
import type { OAuthClient, User } from "../../types/domain"
import { parseScopeString } from "../scopes"
import { evaluateUserTokenAccess } from "../user-token-policy"
import type { TokenResponse } from "./response"

export type IssueUserTokensInput = {
  readonly user: User
  readonly client: OAuthClient
  readonly scope: string
  readonly resource: string
  readonly nonce: string | null
  readonly authTime: number
  readonly sessionId: string | null
  readonly rememberMe?: boolean
  readonly accessValidated?: true
}

/**
 * Assemble a user token response: always an access token, plus an id_token when
 * `openid` was granted and a refresh token when `offline_access` was granted
 * and the client permits it. Shared by the authorization_code and device flows.
 */
export async function issueUserTokens(
  env: Env,
  input: IssueUserTokensInput,
): Promise<TokenResponse> {
  const scopes = parseScopeString(input.scope)
  if (input.accessValidated !== true) {
    const access = await evaluateUserTokenAccess(env, {
      userId: input.user.id,
      clientId: input.client.clientId,
      resourceUri: input.resource,
      scopes,
    })
    if (!access.allowed) {
      throw new OAuthError("invalid_grant", {
        description: "This account is not permitted to access this application or resource.",
        detail: `user token policy denied ${access.reason}`,
      })
    }
  }
  const accessToken = await issueUserAccessToken(env, {
    userId: input.user.id,
    clientId: input.client.clientId,
    resource: input.resource,
    scope: input.scope,
  })
  const response: TokenResponse = {
    access_token: accessToken.token,
    token_type: "Bearer",
    expires_in: accessToken.expiresIn,
    scope: input.scope,
  }
  if (scopes.includes("openid")) {
    response.id_token = await issueIdToken(env, {
      user: input.user,
      clientId: input.client.clientId,
      scopes,
      authTime: input.authTime,
      nonce: input.nonce,
    })
  }
  if (
    scopes.includes("offline_access") &&
    input.client.allowedGrantTypes.includes("refresh_token")
  ) {
    const refresh = await issueRefreshToken(env, {
      userId: input.user.id,
      clientId: input.client.clientId,
      sessionId: input.sessionId,
      resource: input.resource,
      scope: input.scope,
      authTime: input.authTime,
      rememberMe: input.rememberMe ?? false,
    })
    response.refresh_token = refresh.token
  }
  return response
}
