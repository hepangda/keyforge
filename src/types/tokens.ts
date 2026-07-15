/**
 * Payloads carried by the strong-consistency Durable Objects and short-lived
 * grants. These are internal, already-trusted shapes (not boundary input), so
 * they are plain readonly types.
 */

/** Data bound to a single-use authorization code (Phase 7). */
export type AuthorizationCodePayload = {
  readonly clientId: string
  readonly userId: string
  readonly redirectUri: string
  readonly scope: string
  readonly resource: string
  readonly codeChallenge: string
  readonly codeChallengeMethod: "S256"
  readonly nonce: string | null
  readonly authTime: number
  readonly sessionId: string
}

export const ONE_TIME_TOKEN_PURPOSES = [
  "magic_link",
  "email_verification",
  "email_change",
  "password_reset",
  "account_invitation",
] as const
export type OneTimeTokenPurpose = (typeof ONE_TIME_TOKEN_PURPOSES)[number]

/** Data bound to a magic-link / email-verification / recovery capability. */
export type AccountOneTimeTokenPayload = {
  readonly purpose: OneTimeTokenPurpose
  readonly userId: string
  readonly email: string
  readonly redirectTo: string | null
  /** Account security epoch at issue; any security transition invalidates it. */
  readonly securityVersion: number
  /** Whether successful login must mint an OIDC reauthentication proof. */
  readonly reauthenticate?: boolean
}

export type OneTimeTokenPayload = AccountOneTimeTokenPayload

/** Data bound to a WebAuthn challenge (Phase 11). */
export type WebAuthnChallengePayload = {
  readonly kind: "registration" | "authentication"
  readonly challenge: string
  readonly userId: string | null
}
