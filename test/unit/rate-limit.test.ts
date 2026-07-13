import { describe, expect, it } from "vitest"
import type { RateLimitResult } from "../../src/do/RateLimitDO"
import { shouldAuditRateLimit } from "../../src/security/rate-limit"

function result(allowed: boolean, firstDenied: boolean): RateLimitResult {
  return { allowed, firstDenied, remaining: 0, retryAfterSeconds: allowed ? 0 : 60 }
}

describe("rate-limit denial auditing", () => {
  it("audits only when at least one key first crosses its limit", () => {
    expect(shouldAuditRateLimit(result(false, true), result(false, false))).toBe(true)
    expect(shouldAuditRateLimit(result(false, false), result(false, false))).toBe(false)
    expect(shouldAuditRateLimit(result(true, false), result(true, false))).toBe(false)
  })
})
