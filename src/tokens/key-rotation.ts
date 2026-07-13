import type { JWK } from "jose"
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK } from "jose"
import { z } from "zod"
import { KV_KEYS } from "../config"
import { AppError } from "../security/errors"
import { nowSeconds } from "../utils/time"

const ALG = "RS256"
const MODULUS_LENGTH = 2048
/** Keep public-only keys through the longest browser session for logout hints. */
const RETIRED_GRACE_SECONDS = 91 * 24 * 60 * 60
/** Must exceed the public JWKS cache lifetime before a staged key can sign. */
export const JWKS_PROPAGATION_SECONDS = 2 * 60
const ROTATION_LEASE_SECONDS = 120
const ROTATION_LEASE_NAME = "signing-key-write"
const LEGACY_KV_CLEANUP_STATE_KEY = "signing_key_legacy_kv_cleanup_pending"

const jwkSchema = z.custom<JWK>(
  (value) => typeof value === "object" && value !== null && "kty" in value,
)

const storedKeySchema = z.object({
  kid: z.string(),
  // Retired keys deliberately retain only public material. Active and staged
  // keys still require private material and are checked at their use sites.
  privateJwk: jwkSchema.optional(),
  publicJwk: jwkSchema,
  createdAt: z.number(),
  retiredAt: z.number().nullable(),
})
const storedKeysSchema = z.array(storedKeySchema)
const keyringSchema = z
  .object({
    activeKid: z.string(),
    pendingKid: z.string().nullable().optional(),
    pendingSince: z.number().nullable().optional(),
    keys: storedKeysSchema,
  })
  .transform((value) => ({
    ...value,
    pendingKid: value.pendingKid ?? null,
    pendingSince: value.pendingSince ?? null,
  }))

type StoredSigningKey = z.infer<typeof storedKeySchema>
type StoredKeyring = z.infer<typeof keyringSchema>
type PersistedKeyring = { readonly keyring: StoredKeyring; readonly version: number }

export type ActiveSigningKey = {
  readonly kid: string
  readonly privateKey: CryptoKey
}

/** Per-isolate cache of imported private keys, keyed by kid. */
const privateKeyCache = new Map<string, CryptoKey>()

function publishedKeys(keyring: StoredKeyring, now = nowSeconds()): readonly StoredSigningKey[] {
  return keyring.keys.filter(
    (key) =>
      key.kid === keyring.activeKid ||
      key.kid === keyring.pendingKid ||
      (key.retiredAt !== null && now - key.retiredAt < RETIRED_GRACE_SECONDS),
  )
}

function hasUsableActiveKey(keyring: StoredKeyring): boolean {
  return keyring.keys.some(
    (key) =>
      key.kid === keyring.activeKid && key.retiredAt === null && key.privateJwk !== undefined,
  )
}

async function loadPersistedKeyring(env: Env): Promise<PersistedKeyring | null> {
  const row = await env.DB.prepare(
    `SELECT keyring_json, version,
            EXISTS(
              SELECT 1 FROM maintenance_state WHERE key = ?
            ) AS legacy_cleanup_pending
     FROM signing_key_state WHERE id = 1`,
  )
    .bind(LEGACY_KV_CLEANUP_STATE_KEY)
    .first<{ keyring_json: string; version: number; legacy_cleanup_pending: number }>()
  if (row === null) return null
  const keyring = keyringSchema.parse(JSON.parse(row.keyring_json))
  if (!hasUsableActiveKey(keyring)) {
    throw new AppError(500, "Signing key unavailable", {
      detail: "persisted D1 keyring has no usable active private key",
    })
  }
  if (row.legacy_cleanup_pending === 1) {
    await retryLegacyKvCleanup(env)
  }
  return { keyring, version: row.version }
}

async function loadLegacyKeyring(env: Env): Promise<StoredKeyring | null> {
  const [rawKeys, activeKid] = await Promise.all([
    env.KV.get(KV_KEYS.signingKeys),
    env.KV.get(KV_KEYS.activeKid),
  ])
  if (rawKeys === null || activeKid === null) return null
  const candidate = keyringSchema.parse({
    activeKid,
    keys: storedKeysSchema.parse(JSON.parse(rawKeys)),
  })
  return hasUsableActiveKey(candidate) ? candidate : null
}

async function persistKeyring(
  env: Env,
  keyring: StoredKeyring,
  expectedVersion: number | null,
  updatedAt: number,
): Promise<number> {
  const encoded = JSON.stringify(keyring)
  if (expectedVersion === null) {
    const inserted = await env.DB.prepare(
      `INSERT INTO signing_key_state (id, keyring_json, version, updated_at)
       VALUES (1, ?, 1, ?) ON CONFLICT(id) DO NOTHING`,
    )
      .bind(encoded, updatedAt)
      .run()
    if (inserted.meta.changes !== 1) {
      throw new AppError(503, "Signing key state changed concurrently")
    }
    return 1
  }
  const updated = await env.DB.prepare(
    `UPDATE signing_key_state
     SET keyring_json = ?, version = version + 1, updated_at = ?
     WHERE id = 1 AND version = ?`,
  )
    .bind(encoded, updatedAt, expectedVersion)
    .run()
  if (updated.meta.changes !== 1) {
    throw new AppError(503, "Signing key state changed concurrently")
  }
  return expectedVersion + 1
}

async function markLegacyKvCleanupPending(env: Env): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO maintenance_state (key, value, updated_at) VALUES (?, 'pending', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
  )
    .bind(LEGACY_KV_CLEANUP_STATE_KEY, nowSeconds())
    .run()
}

async function clearLegacyKvCleanupPending(env: Env): Promise<void> {
  await env.DB.prepare("DELETE FROM maintenance_state WHERE key = ?")
    .bind(LEGACY_KV_CLEANUP_STATE_KEY)
    .run()
}

async function readLegacyKvCopies(
  env: Env,
): Promise<{ readonly signingKeys: boolean; readonly activeKid: boolean }> {
  const [rawKeys, activeKid] = await Promise.all([
    env.KV.get(KV_KEYS.signingKeys),
    env.KV.get(KV_KEYS.activeKid),
  ])
  return { signingKeys: rawKeys !== null, activeKid: activeKid !== null }
}

/** Remove and verify both pre-D1 private-key copies, then clear the durable marker. */
async function removeLegacyKvKeyring(env: Env): Promise<void> {
  await Promise.all([env.KV.delete(KV_KEYS.signingKeys), env.KV.delete(KV_KEYS.activeKid)])
  const remaining = await readLegacyKvCopies(env)
  if (remaining.signingKeys || remaining.activeKid) {
    throw new Error("legacy signing-key KV copies remain after deletion")
  }
  await clearLegacyKvCleanupPending(env)
}

/** Retry on every keyring load while the durable pending marker remains. */
async function retryLegacyKvCleanup(env: Env): Promise<void> {
  try {
    await removeLegacyKvKeyring(env)
  } catch (error) {
    console.error("signing_keys.legacy_kv_cleanup_failed", error)
  }
}

/**
 * Readiness guard for both current pending migrations and orphaned copies left
 * by an older Worker that did not persist cleanup failure state.
 */
export async function assertLegacySigningKeyCleanupComplete(env: Env): Promise<void> {
  const state = await env.DB.prepare(
    `SELECT
       EXISTS(SELECT 1 FROM signing_key_state WHERE id = 1) AS has_d1_keyring,
       EXISTS(SELECT 1 FROM maintenance_state WHERE key = ?) AS cleanup_pending`,
  )
    .bind(LEGACY_KV_CLEANUP_STATE_KEY)
    .first<{ has_d1_keyring: number; cleanup_pending: number }>()
  const copies = await readLegacyKvCopies(env)
  if (!copies.signingKeys && !copies.activeKid && state?.cleanup_pending !== 1) return
  if (state?.has_d1_keyring !== 1) {
    throw new Error("legacy signing-key KV cleanup cannot run before D1 key initialization")
  }
  await markLegacyKvCleanupPending(env)
  await removeLegacyKvKeyring(env)
}

async function generateStoredKey(createdAt: number): Promise<StoredSigningKey> {
  const { publicKey, privateKey } = await generateKeyPair(ALG, {
    modulusLength: MODULUS_LENGTH,
    extractable: true,
  })
  const publicJwk = await exportJWK(publicKey)
  const privateJwk = await exportJWK(privateKey)
  const kid = await calculateJwkThumbprint(publicJwk)
  publicJwk.kid = kid
  publicJwk.alg = ALG
  publicJwk.use = "sig"
  return { kid, privateJwk, publicJwk, createdAt, retiredAt: null }
}

async function rotatePersistedKeyring(env: Env, rotatedAt: number): Promise<StoredKeyring> {
  const persisted = await loadPersistedKeyring(env)
  const legacy = persisted === null ? await loadLegacyKeyring(env) : null
  const current = persisted?.keyring ?? legacy
  let keyring: StoredKeyring

  if (current === null) {
    // First boot has no previously cached JWKS to protect, so it may become
    // active immediately.
    const initial = await generateStoredKey(rotatedAt)
    keyring = {
      activeKid: initial.kid,
      pendingKid: null,
      pendingSince: null,
      keys: [initial],
    }
  } else if (current.pendingKid === null) {
    // Phase 1: publish the next public key while continuing to sign with the
    // current key. Consumers get at least one full cache lifetime to observe it.
    const pending = await generateStoredKey(rotatedAt)
    const retained = current.keys
      .map((key) => (key.retiredAt === null ? key : { ...key, privateJwk: undefined }))
      .filter((key) => key.retiredAt === null || rotatedAt - key.retiredAt < RETIRED_GRACE_SECONDS)
    keyring = {
      activeKid: current.activeKid,
      pendingKid: pending.kid,
      pendingSince: rotatedAt,
      keys: [pending, ...retained],
    }
  } else {
    const pendingSince = current.pendingSince
    if (pendingSince === null || rotatedAt - pendingSince < JWKS_PROPAGATION_SECONDS) {
      return current
    }
    const pending = current.keys.find(
      (key) =>
        key.kid === current.pendingKid && key.retiredAt === null && key.privateJwk !== undefined,
    )
    if (pending === undefined) {
      throw new AppError(500, "Pending signing key unavailable")
    }
    // Phase 2: activate the pre-published key. Strip private material from the
    // old active key in the same versioned D1 write.
    const activated = current.keys
      .map((key) => {
        if (key.kid === current.activeKid) {
          return { ...key, privateJwk: undefined, retiredAt: rotatedAt }
        }
        if (key.kid === pending.kid) return { ...key, retiredAt: null }
        return key.retiredAt === null ? key : { ...key, privateJwk: undefined }
      })
      .filter((key) => key.retiredAt === null || rotatedAt - key.retiredAt < RETIRED_GRACE_SECONDS)
    privateKeyCache.delete(current.activeKid)
    keyring = {
      activeKid: pending.kid,
      pendingKid: null,
      pendingSince: null,
      keys: activated,
    }
  }
  if (legacy !== null) await markLegacyKvCleanupPending(env)
  await persistKeyring(env, keyring, persisted?.version ?? null, nowSeconds())
  if (legacy !== null) await retryLegacyKvCleanup(env)
  return keyring
}

async function acquireRotationLease(env: Env, ownerToken: string, now: number): Promise<boolean> {
  const result = await env.DB.prepare(
    `INSERT INTO maintenance_leases (job_name, owner_token, lease_until, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(job_name) DO UPDATE SET
       owner_token = excluded.owner_token,
       lease_until = excluded.lease_until,
       updated_at = excluded.updated_at
     WHERE maintenance_leases.lease_until <= ?`,
  )
    .bind(ROTATION_LEASE_NAME, ownerToken, now + ROTATION_LEASE_SECONDS, now, now)
    .run()
  return result.meta.changes === 1
}

async function releaseRotationLease(env: Env, ownerToken: string): Promise<void> {
  await env.DB.prepare("DELETE FROM maintenance_leases WHERE job_name = ? AND owner_token = ?")
    .bind(ROTATION_LEASE_NAME, ownerToken)
    .run()
}

/** Rotate under a D1 lease; D1 is the sole strong-consistency authority. */
export async function rotateSigningKey(env: Env, rotatedAt = nowSeconds()): Promise<string> {
  const ownerToken = crypto.randomUUID()
  if (!(await acquireRotationLease(env, ownerToken, nowSeconds()))) {
    throw new AppError(503, "Signing key rotation is already in progress")
  }
  try {
    return (await rotatePersistedKeyring(env, rotatedAt)).activeKid
  } finally {
    await releaseRotationLease(env, ownerToken)
  }
}

async function ensureKeyring(env: Env): Promise<StoredKeyring> {
  const current = await loadPersistedKeyring(env)
  if (current !== null && hasUsableActiveKey(current.keyring)) return current.keyring

  const ownerToken = crypto.randomUUID()
  if (await acquireRotationLease(env, ownerToken, nowSeconds())) {
    try {
      const afterLease = await loadPersistedKeyring(env)
      if (afterLease !== null && hasUsableActiveKey(afterLease.keyring)) {
        return afterLease.keyring
      }
      if (afterLease === null) {
        const legacy = await loadLegacyKeyring(env)
        if (legacy !== null) {
          await markLegacyKvCleanupPending(env)
          await persistKeyring(env, legacy, null, nowSeconds())
          await retryLegacyKvCleanup(env)
          return legacy
        }
      }
      return rotatePersistedKeyring(env, nowSeconds())
    } finally {
      await releaseRotationLease(env, ownerToken)
    }
  }

  for (let attempt = 0; attempt < 40; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 50))
    const initialized = await loadPersistedKeyring(env)
    if (initialized !== null && hasUsableActiveKey(initialized.keyring)) {
      return initialized.keyring
    }
  }
  throw new AppError(503, "Signing key initialization is still in progress")
}

export type SigningKeyStatus = {
  readonly kid: string
  readonly createdAt: number
  readonly publishedKeyCount: number
  readonly pendingKid: string | null
  readonly pendingSince: number | null
}

/** Inspect the active key without bootstrapping or exposing private material. */
export async function getSigningKeyStatus(env: Env): Promise<SigningKeyStatus | null> {
  const persisted = await loadPersistedKeyring(env)
  if (persisted === null) return null
  const active = persisted.keyring.keys.find(
    (key) => key.kid === persisted.keyring.activeKid && key.retiredAt === null,
  )
  if (active === undefined) {
    throw new AppError(500, "Signing key unavailable", {
      detail: `active kid ${persisted.keyring.activeKid} not present as an active key`,
    })
  }
  return {
    kid: active.kid,
    createdAt: active.createdAt,
    publishedKeyCount: publishedKeys(persisted.keyring).length,
    pendingKid: persisted.keyring.pendingKid,
    pendingSince: persisted.keyring.pendingSince,
  }
}

/** Return the active private signing key, bootstrapping one on first use. */
export async function getActiveSigningKey(env: Env): Promise<ActiveSigningKey> {
  const keyring = await ensureKeyring(env)
  const activeKid = keyring.activeKid
  const cached = privateKeyCache.get(activeKid)
  if (cached !== undefined) return { kid: activeKid, privateKey: cached }

  const found = keyring.keys.find((key) => key.kid === activeKid && key.retiredAt === null)
  if (found === undefined || found.privateJwk === undefined) {
    throw new AppError(500, "Signing key unavailable", {
      detail: `active kid ${activeKid} not present in key set`,
    })
  }
  const imported = await importJWK(found.privateJwk, ALG)
  if (!(imported instanceof CryptoKey)) {
    throw new AppError(500, "Signing key unavailable", {
      detail: "imported key is not a CryptoKey",
    })
  }
  privateKeyCache.set(activeKid, imported)
  return { kid: activeKid, privateKey: imported }
}

/** Public JWK set; expired retired keys are never trusted or published. */
export async function getPublicJwks(env: Env): Promise<{ readonly keys: readonly JWK[] }> {
  const keyring = await ensureKeyring(env)
  return { keys: publishedKeys(keyring).map((key) => key.publicJwk) }
}
