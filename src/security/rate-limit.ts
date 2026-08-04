import type { RateLimitResult } from "../do/RateLimitDO"
import { isYoloEnabled, noteYoloBypass } from "../operations/yolo"

/** An always-allowed result, shaped so callers need no YOLO-specific branch. */
const YOLO_ALLOWED: RateLimitResult = {
  allowed: true,
  remaining: Number.MAX_SAFE_INTEGER,
  retryAfterSeconds: 0,
  firstDenied: false,
}

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
  // YOLO mode never counts a hit, so a dev loop cannot lock itself out.
  if (isYoloEnabled(env)) {
    noteYoloBypass(`rate-limit:${key}`)
    return Promise.resolve(YOLO_ALLOWED)
  }
  return env.RATE_LIMIT.getByName(key).check(limit, windowSeconds)
}
