import { DurableObject } from "cloudflare:workers"

export type ConsumeResult<T> =
  | { readonly found: true; readonly value: T }
  | { readonly found: false }

/**
 * Base for single-use token stores (authorization codes, magic-link tokens,
 * WebAuthn challenges). Each DO instance is addressed by the token/code hash,
 * so it holds exactly one item. The Durable Object input gate serializes
 * access, which — together with the not-consumed check — guarantees a value is
 * consumed at most once even under concurrent requests.
 */
export abstract class OneTimeConsumeDO<T> extends DurableObject<Env> {
  /** Store the value with a TTL. Overwrites any prior value at this instance. */
  async store(value: T, ttlSeconds: number): Promise<void> {
    const expiresAt = Date.now() + ttlSeconds * 1000
    await this.ctx.storage.put<T | number | boolean>({ value, expiresAt, consumed: false })
    await this.ctx.storage.setAlarm(expiresAt + 60_000)
  }

  /** Return the value exactly once; subsequent calls (or expiry) return not-found. */
  async consume(): Promise<ConsumeResult<T>> {
    const consumed = await this.ctx.storage.get<boolean>("consumed")
    if (consumed !== false) {
      return { found: false }
    }
    const expiresAt = await this.ctx.storage.get<number>("expiresAt")
    if (expiresAt === undefined || Date.now() > expiresAt) {
      await this.ctx.storage.deleteAll()
      return { found: false }
    }
    const value = await this.ctx.storage.get<T>("value")
    if (value === undefined) {
      return { found: false }
    }
    await this.ctx.storage.put("consumed", true)
    return { found: true, value }
  }

  /** Read-only peek without consuming (returns not-found if expired/consumed). */
  async peek(): Promise<ConsumeResult<T>> {
    const consumed = await this.ctx.storage.get<boolean>("consumed")
    const expiresAt = await this.ctx.storage.get<number>("expiresAt")
    const value = await this.ctx.storage.get<T>("value")
    if (
      consumed !== false ||
      expiresAt === undefined ||
      Date.now() > expiresAt ||
      value === undefined
    ) {
      return { found: false }
    }
    return { found: true, value }
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll()
  }
}
