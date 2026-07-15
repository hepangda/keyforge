import type { User } from "../types/domain"

export type UserClaims = {
  readonly email?: string
  readonly email_verified?: boolean
  readonly name?: string
  readonly preferred_username?: string
  readonly picture?: string
  readonly groups?: readonly string[]
}

type MutableUserClaims = {
  email?: string
  email_verified?: boolean
  name?: string
  preferred_username?: string
  picture?: string
  groups?: string[]
}

/**
 * Assemble the OIDC claims a user is entitled to for the granted scopes.
 * Every optional claim is gated on the scope that authorizes its release.
 */
export function buildUserClaims(
  user: User,
  groups: readonly string[],
  scopes: readonly string[],
): UserClaims {
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
    if (user.picture !== null) {
      claims.picture = user.picture
    }
  }
  if (scopeSet.has("groups")) {
    claims.groups = [...groups]
  }
  return claims
}
