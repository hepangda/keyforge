import { DurableObject } from "cloudflare:workers"

export type RateLimitResult = {
  readonly allowed: boolean
  readonly remaining: number
  readonly retryAfterSeconds: number
  /** True only for the first request that crosses the limit in this window. */
  readonly firstDenied: boolean
}

/**
 * Fixed-window rate limiter. Addressed by a caller-chosen key
 * (e.g. `login:ip:<hash>`, `token:client:<id>`, `device:usercode`). One DO
 * instance per key; the input gate serializes increments.
 */
export class RateLimitDO extends DurableObject<Env> {
  /** Read-only dependency probe used by the Worker readiness endpoint. */
  ping(): "ok" {
    return "ok"
  }

  /** Count one hit against `limit` per `windowSeconds`; report if allowed. */
  async check(limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const now = Date.now()
    const windowMs = windowSeconds * 1000
    const storedStart = (await this.ctx.storage.get<number>("windowStart")) ?? 0
    const storedCount = (await this.ctx.storage.get<number>("count")) ?? 0

    const newWindow = now - storedStart >= windowMs
    const windowStart = newWindow ? now : storedStart
    // Saturate at limit + 1. Once denied, repeated traffic performs no durable
    // counter/alarm writes and cannot grow this object's state without bound.
    const count = newWindow ? 1 : Math.min(storedCount + 1, limit + 1)
    if (newWindow) {
      await this.ctx.storage.put({ windowStart, count })
      await this.ctx.storage.setAlarm(windowStart + windowMs + 1000)
    } else if (count !== storedCount) {
      await this.ctx.storage.put("count", count)
    }

    const allowed = count <= limit
    const firstDenied = !allowed && (newWindow || storedCount <= limit)
    const retryAfterSeconds = allowed ? 0 : Math.ceil((windowStart + windowMs - now) / 1000)
    return { allowed, remaining: Math.max(0, limit - count), retryAfterSeconds, firstDenied }
  }

  /** Clear the counter (admin unblock). */
  async reset(): Promise<void> {
    await this.ctx.storage.deleteAll()
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll()
  }
}
