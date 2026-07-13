import { computeS256Challenge, isValidCodeVerifier } from "../oauth/pkce"
import { timingSafeEqualString } from "../security/crypto"
import type { AuthorizationCodePayload } from "../types/tokens"
import { OneTimeConsumeDO } from "./base"

/** Single-use OAuth authorization code (Phase 7). Addressed by code hash. */
export class AuthorizationCodeDO extends OneTimeConsumeDO<AuthorizationCodePayload> {
  /**
   * Validate every attacker-controlled code binding and consume in one storage
   * transaction. Invalid guesses never burn a legitimate authorization code.
   */
  async consumeIf(input: {
    readonly clientId: string
    readonly redirectUri: string
    readonly codeVerifier: string
  }): Promise<
    | { readonly found: true; readonly value: AuthorizationCodePayload }
    | { readonly found: false; readonly reason: "not_found" | "binding" | "pkce" }
  > {
    const computedChallenge = isValidCodeVerifier(input.codeVerifier)
      ? await computeS256Challenge(input.codeVerifier)
      : null
    return this.ctx.storage.transaction(async (transaction) => {
      const [consumed, expiresAt, value] = await Promise.all([
        transaction.get<boolean>("consumed"),
        transaction.get<number>("expiresAt"),
        transaction.get<AuthorizationCodePayload>("value"),
      ])
      if (
        consumed !== false ||
        expiresAt === undefined ||
        Date.now() > expiresAt ||
        value === undefined
      ) {
        return { found: false as const, reason: "not_found" as const }
      }
      if (value.clientId !== input.clientId || value.redirectUri !== input.redirectUri) {
        return { found: false as const, reason: "binding" as const }
      }
      if (
        computedChallenge === null ||
        !timingSafeEqualString(computedChallenge, value.codeChallenge)
      ) {
        return { found: false as const, reason: "pkce" as const }
      }
      await transaction.put("consumed", true)
      return { found: true as const, value }
    })
  }
}
