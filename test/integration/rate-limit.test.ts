import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

describe("RateLimitDO denial saturation", () => {
  it("reports only the first denial in a fixed window", async () => {
    const limiter = env.RATE_LIMIT.getByName("test:rate-limit:first-denial")
    await limiter.reset()

    expect(await limiter.check(2, 300)).toMatchObject({
      allowed: true,
      remaining: 1,
      firstDenied: false,
    })
    expect(await limiter.check(2, 300)).toMatchObject({
      allowed: true,
      remaining: 0,
      firstDenied: false,
    })
    const firstDenial = await limiter.check(2, 300)
    expect(firstDenial.allowed).toBe(false)
    expect(firstDenial.firstDenied).toBe(true)
    expect(firstDenial.retryAfterSeconds).toBeGreaterThan(0)

    const repeatedDenial = await limiter.check(2, 300)
    expect(repeatedDenial.allowed).toBe(false)
    expect(repeatedDenial.remaining).toBe(0)
    expect(repeatedDenial.firstDenied).toBe(false)
  })
})
