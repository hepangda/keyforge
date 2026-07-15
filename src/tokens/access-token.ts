import type { JWTPayload } from "jose"
import { JWT_TYP, TOKEN_TTL } from "../config"
import { generateId, ID_PREFIX } from "../utils/id"
import { signJwt } from "./jwt"

export type IssuedToken = {
  readonly token: string
  readonly expiresIn: number
  readonly jti: string
}

export type ServiceAccessTokenParams = {
  readonly clientId: string
  readonly resource: string
  readonly scope: string
}

/**
 * Issue a machine-to-machine (client_credentials) access token. The subject is
 * `client:{id}` and `actor_type=service` so a resource server can never
 * mistake it for a user token. No id_token or refresh_token is ever paired.
 */
export async function issueServiceAccessToken(
  env: Env,
  params: ServiceAccessTokenParams,
): Promise<IssuedToken> {
  const jti = generateId(ID_PREFIX.accessToken)
  const claims: JWTPayload = {
    iss: env.ISSUER,
    sub: `client:${params.clientId}`,
    aud: params.resource,
    azp: params.clientId,
    client_id: params.clientId,
    scope: params.scope,
    actor_type: "service",
    token_use: "access_token",
    jti,
  }
  const token = await signJwt(env, claims, {
    typ: JWT_TYP.accessToken,
    expiresInSeconds: TOKEN_TTL.serviceAccessToken,
  })
  return { token, expiresIn: TOKEN_TTL.serviceAccessToken, jti }
}

export type UserAccessTokenParams = {
  readonly userId: string
  readonly clientId: string
  readonly resource: string
  readonly scope: string
}

export async function issueUserAccessToken(
  env: Env,
  params: UserAccessTokenParams,
): Promise<IssuedToken> {
  const jti = generateId(ID_PREFIX.accessToken)
  const claims: JWTPayload = {
    iss: env.ISSUER,
    sub: params.userId,
    aud: params.resource,
    azp: params.clientId,
    client_id: params.clientId,
    scope: params.scope,
    token_use: "access_token",
    jti,
  }
  const token = await signJwt(env, claims, {
    typ: JWT_TYP.accessToken,
    expiresInSeconds: TOKEN_TTL.userAccessToken,
  })
  return { token, expiresIn: TOKEN_TTL.userAccessToken, jti }
}
