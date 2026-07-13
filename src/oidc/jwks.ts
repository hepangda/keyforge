import type { JWK } from "jose"
import { getPublicJwks } from "../tokens/key-rotation"

/** The `/.well-known/jwks.json` document: every currently-published public key. */
export function buildJwksDocument(env: Env): Promise<{ readonly keys: readonly JWK[] }> {
  return getPublicJwks(env)
}
