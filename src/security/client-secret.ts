import { randomToken } from "../utils/random"
import { sha256Hex, timingSafeEqualString } from "./crypto"

// Client secrets are high-entropy (256-bit random), so a single SHA-256 is
// sufficient — brute force is infeasible — and avoids scrypt cost on the
// machine-to-machine token hot path where passwords would be too slow.

export function generateClientSecret(): string {
  return randomToken(32)
}

export function hashClientSecret(secret: string): Promise<string> {
  return sha256Hex(secret)
}

export async function verifyClientSecret(presented: string, storedHash: string): Promise<boolean> {
  return timingSafeEqualString(await sha256Hex(presented), storedHash)
}
