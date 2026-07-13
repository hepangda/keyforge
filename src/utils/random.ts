import { base64UrlEncode } from "./base64url"

/** Cryptographically secure random bytes from the Workers CSPRNG. */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

/** High-entropy opaque token: base64url of `byteLength` random bytes (default 256-bit). */
export function randomToken(byteLength = 32): string {
  return base64UrlEncode(randomBytes(byteLength))
}

/** Crockford base32 alphabet with ambiguous letters (I, L, O, U) removed. */
const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTVWXYZ23456789"

/**
 * Human-typeable device user_code in `XXXX-XXXX` form, drawn without modulo
 * bias from a CSPRNG.
 */
export function generateUserCode(groups = 2, groupSize = 4): string {
  const total = groups * groupSize
  const chars = new Array<string>(total)
  const alphabetLen = USER_CODE_ALPHABET.length
  const max = Math.floor(256 / alphabetLen) * alphabetLen
  let produced = 0
  while (produced < total) {
    for (const byte of randomBytes(total)) {
      if (produced >= total) {
        break
      }
      if (byte < max) {
        chars[produced] = USER_CODE_ALPHABET[byte % alphabetLen] as string
        produced += 1
      }
    }
  }
  const segments: string[] = []
  for (let i = 0; i < groups; i += 1) {
    segments.push(chars.slice(i * groupSize, (i + 1) * groupSize).join(""))
  }
  return segments.join("-")
}
