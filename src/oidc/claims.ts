import type { User, UserType } from "../types/domain"

export type UserClaims = {
  readonly email?: string
  readonly email_verified?: boolean
  readonly name?: string
  readonly picture?: string
  readonly groups?: readonly string[]
  readonly user_type?: UserType
}

type MutableUserClaims = {
  email?: string
  email_verified?: boolean
  name?: string
  picture?: string
  groups?: string[]
  user_type?: UserType
}

/**
 * Assemble the OIDC claims a user is entitled to for the granted scopes.
 * Every optional claim is gated on the scope that authorizes its release.
 * `groups` covers both group membership and the closely-related user type used
 * by relying parties for workforce authorization decisions.
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
    if (user.name !== null) {
      claims.name = user.name
    }
    if (user.picture !== null) {
      claims.picture = user.picture
    }
  }
  if (scopeSet.has("groups")) {
    claims.groups = [...groups]
    claims.user_type = user.userType
  }
  return claims
}
