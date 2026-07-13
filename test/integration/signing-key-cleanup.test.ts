import { env } from "cloudflare:test"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { health } from "../../src/routes/health"
import {
  assertLegacySigningKeyCleanupComplete,
  getPublicJwks,
  rotateSigningKey,
} from "../../src/tokens/key-rotation"

const CLEANUP_STATE_KEY = "signing_key_legacy_kv_cleanup_pending"
const NOW = 2_000_000_000

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM maintenance_leases WHERE job_name = 'signing-key-write'"),
    env.DB.prepare("DELETE FROM maintenance_state WHERE key = ?").bind(CLEANUP_STATE_KEY),
    env.DB.prepare("DELETE FROM signing_key_state"),
  ])
  await Promise.all([env.KV.delete("signing:keys"), env.KV.delete("signing:active")])
})

async function seedLegacyKvKeyring(): Promise<void> {
  await rotateSigningKey(env, NOW)
  const row = await env.DB.prepare(
    "SELECT keyring_json FROM signing_key_state WHERE id = 1",
  ).first<{
    keyring_json: string
  }>()
  if (row === null) throw new Error("test signing key was not persisted")
  const keyring = JSON.parse(row.keyring_json) as {
    readonly activeKid: string
    readonly keys: readonly unknown[]
  }
  await Promise.all([
    env.KV.put("signing:keys", JSON.stringify(keyring.keys)),
    env.KV.put("signing:active", keyring.activeKid),
  ])
  await env.DB.prepare("DELETE FROM signing_key_state").run()
}

function withFailingKvDeletes(base: Env): Env {
  const failingKv = new Proxy(base.KV, {
    get(target, property) {
      if (property === "delete") {
        return async () => {
          throw new Error("simulated KV deletion failure")
        }
      }
      const value = Reflect.get(target, property)
      return typeof value === "function" ? value.bind(target) : value
    },
  })
  return new Proxy(base, {
    get(target, property) {
      return property === "KV" ? failingKv : Reflect.get(target, property)
    },
  })
}

describe("legacy signing-key KV cleanup", () => {
  it("persists cleanup failure, fails readiness, and retries on the next keyring load", async () => {
    await seedLegacyKvKeyring()
    const failingEnv = withFailingKvDeletes(env)
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined)

    try {
      expect((await getPublicJwks(failingEnv)).keys).toHaveLength(1)
      expect(
        await env.DB.prepare("SELECT value FROM maintenance_state WHERE key = ?")
          .bind(CLEANUP_STATE_KEY)
          .first(),
      ).not.toBeNull()
      expect(await env.KV.get("signing:keys")).not.toBeNull()
      expect(await env.KV.get("signing:active")).not.toBeNull()

      const readiness = await health.request(
        "https://auth.pangda.app/health/ready",
        undefined,
        failingEnv,
      )
      expect(readiness.status).toBe(503)
      const body = await readiness.json<{ checks: Record<string, { status: string }> }>()
      expect(body.checks["signing_keys"]).toEqual({ status: "failed" })
    } finally {
      errorLog.mockRestore()
    }

    expect((await getPublicJwks(env)).keys).toHaveLength(1)
    await expect(assertLegacySigningKeyCleanupComplete(env)).resolves.toBeUndefined()
    expect(
      await env.DB.prepare("SELECT value FROM maintenance_state WHERE key = ?")
        .bind(CLEANUP_STATE_KEY)
        .first(),
    ).toBeNull()
    expect(await env.KV.get("signing:keys")).toBeNull()
    expect(await env.KV.get("signing:active")).toBeNull()
  })
})
