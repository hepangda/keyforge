import {
  createIdentity,
  getIdentityByProvider,
  getIdentityByUserAndProvider,
} from "../db/queries/identities"
import { createUser, getUserByEmail } from "../db/queries/users"

export const SOCIAL_PROVIDERS = ["github", "google"] as const
export type SocialProviderId = (typeof SOCIAL_PROVIDERS)[number]

export type SocialProfile = {
  readonly provider: SocialProviderId
  readonly providerUserId: string
  readonly email: string | null
  readonly emailVerified: boolean
  readonly name: string | null
  readonly picture: string | null
}

export type SocialLoginOutcome =
  | { readonly kind: "login"; readonly userId: string }
  | { readonly kind: "linked"; readonly userId: string }
  | { readonly kind: "created"; readonly userId: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "binding_required"; readonly email: string }
  | { readonly kind: "signup_disabled" }

/**
 * Resolve a social login into an account outcome. Security rules (spec §9):
 *   - a known identity logs in directly;
 *   - if the user is already signed in, the identity links to that account;
 *   - a social profile NEVER takes over an existing local account by email —
 *     an email that matches a local user (while signed out) requires explicit
 *     binding (sign in first, then link);
 *   - otherwise a fresh account is created.
 */
export async function resolveSocialLogin(
  env: Env,
  profile: SocialProfile,
  currentUserId: string | null,
  allowSelfSignup: boolean,
): Promise<SocialLoginOutcome> {
  const identity = await getIdentityByProvider(env, profile.provider, profile.providerUserId)
  if (currentUserId !== null) {
    if (identity !== null) {
      return identity.userId === currentUserId
        ? { kind: "linked", userId: currentUserId }
        : { kind: "conflict" }
    }
    if ((await getIdentityByUserAndProvider(env, currentUserId, profile.provider)) !== null) {
      return { kind: "conflict" }
    }
    await linkIdentity(env, profile, currentUserId)
    return { kind: "linked", userId: currentUserId }
  }

  if (identity !== null) {
    return { kind: "login", userId: identity.userId }
  }

  if (profile.email !== null && (await getUserByEmail(env, profile.email)) !== null) {
    return { kind: "binding_required", email: profile.email }
  }

  if (!allowSelfSignup) {
    return { kind: "signup_disabled" }
  }

  const user = await createUser(env, {
    email: profile.email ?? syntheticEmail(profile),
    name: profile.name,
    picture: profile.picture,
    userType: "external",
    emailVerified: profile.emailVerified,
  })
  await linkIdentity(env, profile, user.id)
  return { kind: "created", userId: user.id }
}

function linkIdentity(env: Env, profile: SocialProfile, userId: string): Promise<void> {
  return createIdentity(env, {
    userId,
    provider: profile.provider,
    providerUserId: profile.providerUserId,
    email: profile.email,
    emailVerified: profile.emailVerified,
    profileJson: JSON.stringify({ name: profile.name, picture: profile.picture }),
  })
}

function syntheticEmail(profile: SocialProfile): string {
  return `${profile.provider}_${profile.providerUserId}@users.noreply.pangda.app`
}
