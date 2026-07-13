import type { WebAuthnChallengePayload } from "../types/tokens"
import { OneTimeConsumeDO } from "./base"

/**
 * Single-use WebAuthn/passkey challenge store (Phase 11). Addressed by a
 * per-ceremony id; the challenge must be consumed exactly once on verify.
 */
export class WebAuthnChallengeDO extends OneTimeConsumeDO<WebAuthnChallengePayload> {}
