import type { JWTPayload } from "jose"
import { JWT_TYP, TOKEN_TTL } from "../config"
import { buildUserClaims } from "../oidc/claims"
import type { User } from "../types/domain"
import { signJwt } from "./jwt"

export type IdTokenParams = {
  readonly user: User
  readonly groups: readonly string[]
  readonly clientId: string
  readonly scopes: readonly string[]
  readonly authTime: number
  readonly nonce: string | null
}

export async function issueIdToken(env: Env, params: IdTokenParams): Promise<string> {
  const claims: JWTPayload = {
    iss: env.ISSUER,
    sub: params.user.id,
    aud: params.clientId,
    auth_time: params.authTime,
    ...buildUserClaims(params.user, params.groups, params.scopes),
  }
  if (params.nonce !== null) {
    claims["nonce"] = params.nonce
  }
  return signJwt(env, claims, { typ: JWT_TYP.idToken, expiresInSeconds: TOKEN_TTL.idToken })
}
