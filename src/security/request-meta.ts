import type { Context } from "hono"
import type { AppBindings } from "../types/app"
import { hmacSha256Hex, sha256Hex } from "./crypto"

export const EMAIL_INPUT_MAX_LENGTH = 254
const INVALID_EMAIL_CORRELATION_VALUE = "<invalid-email-input>"

/** Collapse oversized attacker input before hashing or constructing a keyed limiter. */
export function emailCorrelationValue(value: string): string {
  return value.length <= EMAIL_INPUT_MAX_LENGTH ? value : INVALID_EMAIL_CORRELATION_VALUE
}

export function requestCorrelationHash(env: Env, domain: string, value: string): Promise<string> {
  const secret = env.REQUEST_HASH_SECRET?.trim()
  return secret === undefined || secret === ""
    ? sha256Hex(`${domain}\u0000${value}`)
    : hmacSha256Hex(secret, `${domain}\u0000${value}`)
}

export async function clientIpHash(c: Context<AppBindings>): Promise<string | null> {
  const ip = c.req.header("cf-connecting-ip") ?? c.req.header("x-real-ip")
  return ip === undefined ? null : requestCorrelationHash(c.env, "ip", ip)
}

export async function userAgentHash(c: Context<AppBindings>): Promise<string | null> {
  const userAgent = c.req.header("user-agent")
  return userAgent === undefined ? null : requestCorrelationHash(c.env, "user-agent", userAgent)
}
