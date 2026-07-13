import type { Context } from "hono"
import type { RateLimitResult } from "../do/RateLimitDO"
import type { AppBindings } from "../types/app"
import { checkRateLimit } from "./rate-limit"
import { clientIpHash } from "./request-meta"

const BASE64URL = /^[A-Za-z0-9_-]+$/
const COMPACT_JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

export const ACCESS_TOKEN_MAX_LENGTH = 16 * 1024

/** Exact unpadded base64url syntax for a token generated from this many bytes. */
export function isOpaqueToken(value: string, byteLength: number): boolean {
  return value.length === Math.ceil((byteLength * 4) / 3) && BASE64URL.test(value)
}

export function isAccountCapabilityToken(value: string): boolean {
  return isOpaqueToken(value, 32)
}

export function isWebAuthnCeremonyId(value: string): boolean {
  return isOpaqueToken(value, 16)
}

/** Bound and preflight a compact JWT before loading the D1-backed JWKS. */
export function isPlausibleCompactJwt(value: string): boolean {
  return value.length <= ACCESS_TOKEN_MAX_LENGTH && COMPACT_JWT.test(value)
}

export async function checkIpRateLimit(
  c: Context<AppBindings>,
  namespace: string,
  limit: number,
  windowSeconds = 5 * 60,
): Promise<RateLimitResult> {
  const ipHash = await clientIpHash(c)
  return checkRateLimit(c.env, `${namespace}:ip:${ipHash ?? "unknown"}`, limit, windowSeconds)
}
