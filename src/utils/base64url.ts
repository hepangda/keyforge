/**
 * base64url (RFC 4648 §5, no padding) codec. Used for PKCE, token encoding,
 * and JWK material. Runs on the Workers `btoa`/`atob` globals.
 */

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function base64UrlDecode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/")
  const remainder = normalized.length % 4
  const padded = remainder === 0 ? normalized : normalized + "=".repeat(4 - remainder)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export function base64UrlEncodeString(value: string): string {
  return base64UrlEncode(new TextEncoder().encode(value))
}

export function base64UrlDecodeToString(value: string): string {
  return new TextDecoder().decode(base64UrlDecode(value))
}
