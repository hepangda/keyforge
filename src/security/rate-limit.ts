import type { RateLimitResult } from "../do/RateLimitDO"

/** Emit one denial audit when any participating key first crosses its limit. */
export function shouldAuditRateLimit(...results: readonly RateLimitResult[]): boolean {
  return results.some((result) => !result.allowed && result.firstDenied)
}

/** Count one hit for `key` against `limit` per `windowSeconds` via RateLimitDO. */
export function checkRateLimit(
  env: Env,
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<RateLimitResult> {
  return env.RATE_LIMIT.getByName(key).check(limit, windowSeconds)
}
