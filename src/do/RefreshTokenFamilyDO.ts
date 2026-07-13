import { DurableObject } from "cloudflare:workers"
import { REFRESH_TOKEN_POLICY } from "../config"
import { nowSeconds } from "../utils/time"

export type RefreshFamilyInit = {
  readonly userId: string
  readonly clientId: string
  readonly resource: string
  readonly scope: string
  /** Original end-user authentication instant (UNIX seconds). */
  readonly authTime: number
  readonly currentTokenHash: string
  /** Absolute family expiry (UNIX seconds); rotation cannot extend past this. */
  readonly absoluteExpiresAt: number
}

export type RefreshFamilyMeta = {
  readonly userId: string
  readonly clientId: string
  readonly resource: string
  readonly scope: string
  readonly authTime: number
  readonly absoluteExpiresAt: number
  readonly createdAt: number
  readonly generation: number
  readonly revoked: boolean
  readonly lastRotatedAt: number
}

export type RotateResult =
  | { readonly status: "rotated"; readonly meta: RefreshFamilyMeta }
  | { readonly status: "reuse_detected"; readonly meta: RefreshFamilyMeta }
  | { readonly status: "too_soon"; readonly retryAfterSeconds: number }
  | { readonly status: "generation_limit"; readonly meta: RefreshFamilyMeta }
  | { readonly status: "revoked" }
  | { readonly status: "expired" }
  | { readonly status: "invalid" }

const USED_HASH_PREFIX = "used:"

function usedHashKey(hash: string): string {
  return `${USED_HASH_PREFIX}${hash}`
}

/**
 * Serializes refresh-token rotation for one token family and detects reuse.
 * Addressed by family id, so every rotation for a family runs single-threaded
 * here. Presenting a previously-rotated (used) hash burns the whole family.
 */
export class RefreshTokenFamilyDO extends DurableObject<Env> {
  /** Create the family on first refresh-token issuance. */
  async init(data: RefreshFamilyInit): Promise<void> {
    const now = nowSeconds()
    const meta: RefreshFamilyMeta = {
      userId: data.userId,
      clientId: data.clientId,
      resource: data.resource,
      scope: data.scope,
      authTime: data.authTime,
      absoluteExpiresAt: data.absoluteExpiresAt,
      createdAt: now,
      generation: 0,
      revoked: false,
      lastRotatedAt: now,
    }
    await this.ctx.storage.transaction(async (txn) => {
      if ((await txn.get("meta")) !== undefined) return
      await txn.put("meta", meta)
      await txn.put("currentHash", data.currentTokenHash)
    })
    await this.ctx.storage.setAlarm(data.absoluteExpiresAt * 1000 + 60_000)
  }

  /** Validate the presented refresh token and rotate to a new one. */
  async rotate(
    presentedHash: string,
    newTokenHash: string,
    expectedClientId: string,
    nextScope: string,
  ): Promise<RotateResult> {
    return this.ctx.storage.transaction(async (txn) => {
      const [meta, currentHash, legacyUsedHashes] = await Promise.all([
        txn.get<RefreshFamilyMeta>("meta"),
        txn.get<string>("currentHash"),
        txn.get<readonly string[]>("usedHashes"),
      ])
      if (meta === undefined || currentHash === undefined) {
        return { status: "invalid" }
      }
      // D1 performs the fast client-boundary check before this call. Repeat it
      // inside the serialized authority so D1/DO drift can never rotate a token
      // family on behalf of a different client.
      if (meta.clientId !== expectedClientId) {
        return { status: "invalid" }
      }
      if (meta.revoked) {
        return { status: "revoked" }
      }
      if (nowSeconds() > meta.absoluteExpiresAt) {
        return { status: "expired" }
      }
      if (presentedHash === currentHash) {
        const now = nowSeconds()
        if (meta.generation >= REFRESH_TOKEN_POLICY.maximumGeneration) {
          const burned: RefreshFamilyMeta = { ...meta, revoked: true }
          await txn.put("meta", burned)
          return { status: "generation_limit", meta: burned }
        }
        // Issuance is not a rotation, so generation zero is allowed to rotate
        // immediately. Thereafter this bounds write amplification without
        // consuming or revoking the still-current token.
        const lastRotatedAt = meta.lastRotatedAt ?? meta.createdAt
        const elapsed = Math.max(0, now - lastRotatedAt)
        if (meta.generation > 0 && elapsed < REFRESH_TOKEN_POLICY.minimumRotationIntervalSeconds) {
          return {
            status: "too_soon",
            retryAfterSeconds: REFRESH_TOKEN_POLICY.minimumRotationIntervalSeconds - elapsed,
          }
        }
        const nextMeta: RefreshFamilyMeta = {
          ...meta,
          // Families created before authTime was introduced are upgraded in
          // place. Their creation time is the best preserved approximation.
          authTime: meta.authTime ?? meta.createdAt,
          scope: nextScope,
          generation: meta.generation + 1,
          lastRotatedAt: now,
        }
        // One key per hash avoids a bounded array silently forgetting old
        // rotations. The family alarm removes all keys at absolute expiry.
        await txn.put("meta", nextMeta)
        await txn.put("currentHash", newTokenHash)
        await txn.put(usedHashKey(currentHash), true)
        return { status: "rotated", meta: nextMeta }
      }
      const reused =
        legacyUsedHashes?.includes(presentedHash) === true ||
        (await txn.get<boolean>(usedHashKey(presentedHash))) === true
      if (reused) {
        const burned: RefreshFamilyMeta = { ...meta, revoked: true }
        await txn.put("meta", burned)
        return { status: "reuse_detected", meta: burned }
      }
      return { status: "invalid" }
    })
  }

  /** Revoke the entire family (logout, admin action, or reuse fallout). */
  async revoke(): Promise<void> {
    await this.ctx.storage.transaction(async (txn) => {
      const meta = await txn.get<RefreshFamilyMeta>("meta")
      if (meta !== undefined) await txn.put("meta", { ...meta, revoked: true })
    })
  }

  /** Current family metadata, or null if never initialized. */
  async getState(): Promise<RefreshFamilyMeta | null> {
    return (await this.ctx.storage.get<RefreshFamilyMeta>("meta")) ?? null
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll()
  }
}
