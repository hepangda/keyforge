import { scryptAsync } from "@noble/hashes/scrypt.js"
import { bytesToHex } from "@noble/hashes/utils.js"
import { SCRYPT_PARAMS } from "../config"
import { base64UrlDecode, base64UrlEncode } from "../utils/base64url"
import { randomBytes } from "../utils/random"

/** SHA-256 digest via the native Workers WebCrypto implementation. */
export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return new Uint8Array(digest)
}

/** Lowercase-hex SHA-256 — the canonical at-rest form for opaque tokens. */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  return bytesToHex(await sha256(data))
}

/** Domain-separated, keyed digest for privacy-preserving correlation values. */
export async function hmacSha256Hex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data))
  return bytesToHex(new Uint8Array(signature))
}

/** Constant-time byte comparison. Length is compared first (not secret here). */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  }
  return diff === 0
}

/** Constant-time comparison of two ASCII/hex strings. */
export function timingSafeEqualString(a: string, b: string): boolean {
  const encoder = new TextEncoder()
  return timingSafeEqual(encoder.encode(a), encoder.encode(b))
}

const SCRYPT_SCHEME = "scrypt"

/**
 * Hash a password with scrypt. The output is self-describing
 * (`scrypt$N$r$p$saltB64url$hashB64url`) so parameters can be raised later
 * without invalidating existing hashes.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const derived = await scryptAsync(normalize(password), salt, SCRYPT_PARAMS)
  return [
    SCRYPT_SCHEME,
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    base64UrlEncode(salt),
    base64UrlEncode(derived),
  ].join("$")
}

/** Verify a password against a stored scrypt hash in constant time. */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, nRaw, rRaw, pRaw, saltRaw, hashRaw] = stored.split("$")
  if (
    scheme !== SCRYPT_SCHEME ||
    nRaw === undefined ||
    rRaw === undefined ||
    pRaw === undefined ||
    saltRaw === undefined ||
    hashRaw === undefined
  ) {
    return false
  }
  const N = Number(nRaw)
  const r = Number(rRaw)
  const p = Number(pRaw)
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) {
    return false
  }
  const expected = base64UrlDecode(hashRaw)
  const derived = await scryptAsync(normalize(password), base64UrlDecode(saltRaw), {
    N,
    r,
    p,
    dkLen: expected.length,
  })
  return timingSafeEqual(derived, expected)
}

/** NFKC-normalize then UTF-8 encode, so visually identical passwords hash alike. */
function normalize(password: string): Uint8Array {
  return new TextEncoder().encode(password.normalize("NFKC"))
}
