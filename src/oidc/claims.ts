import { avatarUrl } from "../media/avatar"
import type { User } from "../types/domain"

export type UserClaims = {
  readonly email?: string
  readonly email_verified?: boolean
  readonly name?: string
  readonly preferred_username?: string
  readonly picture?: string
}

type MutableUserClaims = {
  email?: string
  email_verified?: boolean
  name?: string
  preferred_username?: string
  picture?: string
}

/**
 * The `picture` URL a relying party should use: a locally uploaded avatar wins
 * over an externally hosted one, because it is the value the user last chose
 * here. The URL carries an unguessable key and needs no credentials, so an RP
 * can place it straight into an `<img>` tag.
 */
export function effectivePictureUrl(env: Env, user: User): string | null {
  if (user.avatarKey !== null) {
    return avatarUrl(env.ISSUER, user.avatarKey)
  }
  return user.picture
}

/**
 * Assemble the OIDC claims a user is entitled to for the granted scopes.
 * Every optional claim is gated on the scope that authorizes its release.
 */
export function buildUserClaims(env: Env, user: User, scopes: readonly string[]): UserClaims {
  const scopeSet = new Set(scopes)
  const claims: MutableUserClaims = {}
  if (scopeSet.has("email")) {
    claims.email = user.email
    claims.email_verified = user.emailVerified
  }
  if (scopeSet.has("profile")) {
    claims.preferred_username = user.alias
    if (user.name !== null) {
      claims.name = user.name
    }
    const picture = effectivePictureUrl(env, user)
    if (picture !== null) {
      claims.picture = picture
    }
  }
  return claims
}
