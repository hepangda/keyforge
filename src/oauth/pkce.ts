import { sha256, timingSafeEqualString } from "../security/crypto"
import { base64UrlEncode } from "../utils/base64url"

/** Only S256 is supported — `plain` is deliberately rejected. */
export type CodeChallengeMethod = "S256"

/** RFC 7636 §4.2 code_verifier syntax: 43-128 chars from the unreserved set. */
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/
const S256_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/

/** Compute the S256 code challenge (`BASE64URL(SHA256(verifier))`). */
export async function computeS256Challenge(verifier: string): Promise<string> {
  return base64UrlEncode(await sha256(verifier))
}

/** Whether a code_verifier is syntactically valid per RFC 7636. */
export function isValidCodeVerifier(verifier: string): boolean {
  return CODE_VERIFIER_PATTERN.test(verifier)
}

/** S256 is a base64url-encoded 32-byte SHA-256 digest (exactly 43 chars). */
export function isValidS256Challenge(challenge: string): boolean {
  return S256_CHALLENGE_PATTERN.test(challenge)
}

/**
 * Verify a PKCE `code_verifier` against the stored `code_challenge`. Rejects
 * malformed verifiers before hashing; the comparison itself is constant-time.
 */
export async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  if (!isValidCodeVerifier(verifier)) {
    return false
  }
  return timingSafeEqualString(await computeS256Challenge(verifier), challenge)
}
