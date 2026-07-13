import { sha256Hex } from "../security/crypto"

/**
 * Canonical at-rest hash for opaque tokens — refresh tokens, session tokens,
 * device codes, user codes, magic-link tokens. Only the hash is ever stored,
 * so a database read cannot recover a usable credential.
 */
export function hashOpaqueToken(token: string): Promise<string> {
  return sha256Hex(token)
}
