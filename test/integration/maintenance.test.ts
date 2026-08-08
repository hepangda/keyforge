import { env } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { runScheduledMaintenance } from "../../src/operations/maintenance"
import {
  getPublicJwks,
  getSigningKeyStatus,
  JWKS_PROPAGATION_SECONDS,
  rotateSigningKey,
} from "../../src/tokens/key-rotation"

const NOW = 2_000_000_000
const DAY = 24 * 60 * 60

function withPrepareCounter(base: Env, onPrepare: () => void): Env {
  const countingDb = new Proxy(base.DB, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => {
          onPrepare()
          return target.prepare(query)
        }
      }
      const value = Reflect.get(target, property)
      return typeof value === "function" ? value.bind(target) : value
    },
  })
  return new Proxy(base, {
    get(target, property) {
      return property === "DB" ? countingDb : Reflect.get(target, property)
    },
  })
}

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM maintenance_leases"),
    env.DB.prepare("DELETE FROM signing_key_state"),
    env.DB.prepare("DELETE FROM audit_logs WHERE id LIKE 'aud_maintenance_%'"),
    env.DB.prepare("DELETE FROM sessions WHERE id LIKE 'ses_maintenance_%'"),
    env.DB.prepare("DELETE FROM device_authorization_sessions WHERE id LIKE 'dvc_maintenance_%'"),
    env.DB.prepare("DELETE FROM email_verifications WHERE id LIKE 'emv_maintenance_%'"),
    env.DB.prepare("DELETE FROM users WHERE id = 'usr_maintenance_test'"),
  ])
  await Promise.all([env.KV.delete("signing:active"), env.KV.delete("signing:keys")])
  await getSigningKeyStatus(env)
})

describe("scheduled maintenance", () => {
  it("rotates signing keys, directly deletes expired audit rows, and removes terminal data", async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users
          (id, email, alias, email_verified, name, disabled, created_at, updated_at)
         VALUES (?, ?, 'maintenancetest', 1, ?, 0, ?, ?)`,
      ).bind(
        "usr_maintenance_test",
        "maintenance@example.test",
        "Maintenance Test",
        NOW - 100 * DAY,
        NOW - 100 * DAY,
      ),
      env.DB.prepare(
        `INSERT INTO sessions
          (id, user_id, token_hash, auth_method, auth_time, created_at, last_seen_at, expires_at)
         VALUES (?, ?, ?, 'password', ?, ?, ?, ?)`,
      ).bind(
        "ses_maintenance_expired",
        "usr_maintenance_test",
        "maintenance-expired-token",
        NOW - 100 * DAY,
        NOW - 100 * DAY,
        NOW - 100 * DAY,
        NOW - 31 * DAY,
      ),
      env.DB.prepare(
        `INSERT INTO sessions
          (id, user_id, token_hash, auth_method, auth_time, created_at, last_seen_at, expires_at)
         VALUES (?, ?, ?, 'password', ?, ?, ?, ?)`,
      ).bind(
        "ses_maintenance_fresh",
        "usr_maintenance_test",
        "maintenance-fresh-token",
        NOW,
        NOW,
        NOW,
        NOW + DAY,
      ),
      env.DB.prepare(
        `INSERT INTO email_verifications
          (id, user_id, email, token_hash, created_at, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)`,
      ).bind(
        "emv_maintenance_expired",
        "usr_maintenance_test",
        "maintenance@example.test",
        "maintenance-email-token",
        NOW - 100 * DAY,
        NOW - 31 * DAY,
      ),
      env.DB.prepare(
        `INSERT INTO password_reset_tokens
          (id, user_id, token_hash, created_at, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, NULL)`,
      ).bind(
        "pwr_maintenance_expired",
        "usr_maintenance_test",
        "maintenance-password-token",
        NOW - 100 * DAY,
        NOW - 31 * DAY,
      ),
      env.DB.prepare(
        `INSERT INTO refresh_tokens
          (id, token_hash, user_id, client_id, session_id, resource, scope, generation,
           remember_me, auth_time, created_at, last_rotated_at, expires_at, revoked_at)
         VALUES (?, ?, ?, 'pangda_app', NULL, 'https://api.pangda.app', 'api.read', 0,
                 0, ?, ?, ?, ?, NULL)`,
      ).bind(
        "rtf_maintenance_expired",
        "maintenance-refresh-token",
        "usr_maintenance_test",
        NOW - 100 * DAY,
        NOW - 100 * DAY,
        NOW - 100 * DAY,
        NOW - 31 * DAY,
      ),
      env.DB.prepare(
        `INSERT INTO authorization_grants
          (id, user_id, client_id, session_id, scope, resource, grant_type, created_at, revoked_at)
         VALUES (?, ?, 'pangda_app', NULL, 'api.read', 'https://api.pangda.app',
                 'authorization_code', ?, NULL)`,
      ).bind("grt_maintenance_old", "usr_maintenance_test", NOW - 31 * DAY),
      env.DB.prepare(
        `INSERT INTO device_authorization_sessions
          (id, device_code_hash, user_code_hash, client_id, resource_uri, scope, status,
           user_id, expires_at, created_at)
         VALUES (?, ?, ?, 'pangda_cli', 'https://api.pangda.app', 'api.read', 'expired',
                 ?, ?, ?)`,
      ).bind(
        "dvc_maintenance_expired",
        "maintenance-device-code",
        "maintenance-user-code",
        "usr_maintenance_test",
        NOW - 31 * DAY,
        NOW - 100 * DAY,
      ),
      env.DB.prepare(
        `INSERT INTO audit_logs (id, event_type, detail, created_at)
         VALUES (?, 'user.logout', 'expired row', ?)`,
      ).bind("aud_maintenance_expired", NOW - 90 * DAY - 1),
      env.DB.prepare(
        `INSERT INTO audit_logs (id, event_type, detail, created_at)
         VALUES (?, 'user.logout', 'boundary row', ?)`,
      ).bind("aud_maintenance_boundary", NOW - 90 * DAY),
      env.DB.prepare(
        `INSERT INTO audit_logs (id, event_type, detail, created_at)
         VALUES (?, 'user.logout', 'fresh row', ?)`,
      ).bind("aud_maintenance_fresh", NOW),
    ])

    const result = await runScheduledMaintenance(env, NOW)

    expect(result.status).toBe("completed")
    expect(result.signingKeyRotated).toBe(true)
    expect(result.deletedAuditRows).toBe(1)
    expect(result.deletedRows["sessions"]).toBe(1)
    expect(result.deletedRows["refresh_tokens"]).toBe(1)
    expect(result.deletedRows["authorization_grants"]).toBe(1)
    expect(result.deletedRows["device_authorization_sessions"]).toBe(1)
    expect(result.deletedRows["email_verifications"]).toBe(1)
    expect(result.deletedRows["password_reset_tokens"]).toBe(1)
    expect(
      await env.DB.prepare("SELECT id FROM sessions WHERE id = 'ses_maintenance_expired'").first(),
    ).toBeNull()
    expect(
      await env.DB.prepare("SELECT id FROM sessions WHERE id = 'ses_maintenance_fresh'").first(),
    ).not.toBeNull()
    expect(
      await env.DB.prepare(
        "SELECT id FROM audit_logs WHERE id = 'aud_maintenance_expired'",
      ).first(),
    ).toBeNull()
    expect(
      await env.DB.prepare(
        "SELECT id FROM audit_logs WHERE id = 'aud_maintenance_boundary'",
      ).first(),
    ).not.toBeNull()
    expect(
      await env.DB.prepare("SELECT id FROM audit_logs WHERE id = 'aud_maintenance_fresh'").first(),
    ).not.toBeNull()
  })

  it("bounds each audit deletion run and reports the remaining backlog", async () => {
    await env.DB.prepare(
      `WITH digits(d) AS (
         VALUES (0), (1), (2), (3), (4), (5), (6), (7), (8), (9)
       ), sequence(n) AS (
         SELECT ones.d + 10 * tens.d + 100 * hundreds.d + 1000 * thousands.d
         FROM digits AS ones
         CROSS JOIN digits AS tens
         CROSS JOIN digits AS hundreds
         CROSS JOIN digits AS thousands
       )
       INSERT INTO audit_logs (id, event_type, detail, created_at)
       SELECT printf('aud_maintenance_bulk_%04d', n), 'user.logout', 'expired row', ?
       FROM sequence
       WHERE n < 1201`,
    )
      .bind(NOW - 90 * DAY - 1)
      .run()

    const first = await runScheduledMaintenance(env, NOW)

    expect(first.deletedAuditRows).toBe(1200)
    expect(first.auditBacklogRemaining).toBe(1)
    expect(first.oldestEligibleAuditAt).toBe(NOW - 90 * DAY - 1)

    const second = await runScheduledMaintenance(env, NOW + 1)

    expect(second.deletedAuditRows).toBe(1)
    expect(second.auditBacklogRemaining).toBe(0)
    expect(second.oldestEligibleAuditAt).toBeNull()
  })

  it("removes non-expired rows through each secondary terminal-state branch", async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users
          (id, email, alias, email_verified, name, disabled, created_at, updated_at)
         VALUES ('usr_maintenance_test', 'maintenance@example.test', 'maintenancetest', 1,
                 'Maintenance Test', 0, ?, ?)`,
      ).bind(NOW - 100 * DAY, NOW - 100 * DAY),
      env.DB.prepare(
        `INSERT INTO sessions
          (id, user_id, token_hash, auth_method, auth_time, created_at, last_seen_at,
           expires_at, revoked_at)
         VALUES ('ses_maintenance_revoked', 'usr_maintenance_test', 'maintenance-revoked-token',
                 'password', ?, ?, ?, ?, ?)`,
      ).bind(NOW - 100 * DAY, NOW - 100 * DAY, NOW - 100 * DAY, NOW + DAY, NOW - 31 * DAY),
      env.DB.prepare(
        `INSERT INTO sessions
          (id, user_id, token_hash, auth_method, auth_time, created_at, last_seen_at, expires_at)
         VALUES ('ses_maintenance_reauth', 'usr_maintenance_test', 'maintenance-reauth-session',
                 'password', ?, ?, ?, ?)`,
      ).bind(NOW, NOW, NOW, NOW + DAY),
      env.DB.prepare(
        `INSERT INTO refresh_tokens
          (id, token_hash, user_id, client_id, session_id, resource, scope, generation,
           remember_me, auth_time, created_at, last_rotated_at, expires_at, revoked_at)
         VALUES ('rtf_maintenance_revoked', 'maintenance-revoked-refresh',
                 'usr_maintenance_test', 'pangda_app', NULL, 'https://api.pangda.app',
                 'api.read', 0, 0, ?, ?, ?, ?, ?)`,
      ).bind(NOW, NOW - 100 * DAY, NOW - 100 * DAY, NOW + DAY, NOW - 31 * DAY),
      env.DB.prepare(
        `INSERT INTO device_authorization_sessions
          (id, device_code_hash, user_code_hash, client_id, resource_uri, scope, status,
           user_id, expires_at, created_at)
         VALUES ('dvc_maintenance_consumed', 'maintenance-consumed-device',
                 'maintenance-consumed-user-code', 'pangda_cli', 'https://api.pangda.app',
                 'api.read', 'consumed', 'usr_maintenance_test', ?, ?)`,
      ).bind(NOW + DAY, NOW - 31 * DAY),
      env.DB.prepare(
        `INSERT INTO email_verifications
          (id, user_id, email, token_hash, created_at, expires_at, consumed_at)
         VALUES ('emv_maintenance_consumed', 'usr_maintenance_test',
                 'maintenance@example.test', 'maintenance-consumed-email', ?, ?, ?)`,
      ).bind(NOW - 100 * DAY, NOW + DAY, NOW - 31 * DAY),
      env.DB.prepare(
        `INSERT INTO password_reset_tokens
          (id, user_id, token_hash, created_at, expires_at, consumed_at)
         VALUES ('pwr_maintenance_consumed', 'usr_maintenance_test',
                 'maintenance-consumed-password', ?, ?, ?)`,
      ).bind(NOW - 100 * DAY, NOW + DAY, NOW - 31 * DAY),
      env.DB.prepare(
        `INSERT INTO reauth_continuations
          (token_hash, session_id, request_hash, expires_at, created_at, consumed_at)
         VALUES ('maintenance-consumed-reauth', 'ses_maintenance_reauth',
                 'maintenance-request', ?, ?, ?)`,
      ).bind(NOW + DAY, NOW - DAY, NOW - 1),
    ])

    const result = await runScheduledMaintenance(env, NOW)

    expect(result.deletedRows).toMatchObject({
      sessions: 1,
      refresh_tokens: 1,
      device_authorization_sessions: 1,
      email_verifications: 1,
      password_reset_tokens: 1,
      reauth_continuations: 1,
    })
    for (const [table, idColumn, id] of [
      ["sessions", "id", "ses_maintenance_revoked"],
      ["refresh_tokens", "id", "rtf_maintenance_revoked"],
      ["device_authorization_sessions", "id", "dvc_maintenance_consumed"],
      ["email_verifications", "id", "emv_maintenance_consumed"],
      ["password_reset_tokens", "id", "pwr_maintenance_consumed"],
      ["reauth_continuations", "token_hash", "maintenance-consumed-reauth"],
    ] as const) {
      expect(
        await env.DB.prepare(`SELECT 1 FROM ${table} WHERE ${idColumn} = ?`).bind(id).first(),
      ).toBeNull()
    }
    expect(
      await env.DB.prepare("SELECT id FROM sessions WHERE id = 'ses_maintenance_reauth'").first(),
    ).not.toBeNull()
  })

  it("skips an overlapping invocation while the D1 lease is live", async () => {
    await env.DB.prepare(
      `INSERT INTO maintenance_leases (job_name, owner_token, lease_until, updated_at)
       VALUES ('scheduled-maintenance', 'another-run', ?, ?)`,
    )
      .bind(NOW + 300, NOW)
      .run()

    const result = await runScheduledMaintenance(env, NOW)

    expect(result.status).toBe("skipped")
    expect(result.signingKeyRotated).toBe(false)
  })

  it("pre-publishes a due signing key, waits for propagation, and retains the retired public key", async () => {
    await rotateSigningKey(env, NOW - 8 * DAY)
    const previous = await getSigningKeyStatus(env)

    const stagedResult = await runScheduledMaintenance(env, NOW)
    const staged = await getSigningKeyStatus(env)
    const stagedJwks = await getPublicJwks(env)

    expect(stagedResult.signingKeyRotated).toBe(true)
    expect(staged?.kid).toBe(previous?.kid)
    expect(staged?.pendingKid).not.toBeNull()
    expect(staged?.pendingKid).not.toBe(previous?.kid)
    expect(staged?.pendingSince).toBe(NOW)
    expect(stagedJwks.keys.map((key) => key.kid)).toEqual(
      expect.arrayContaining([previous?.kid, staged?.pendingKid]),
    )

    const waitingResult = await runScheduledMaintenance(env, NOW + JWKS_PROPAGATION_SECONDS - 1)
    const waiting = await getSigningKeyStatus(env)

    expect(waitingResult.signingKeyRotated).toBe(false)
    expect(waiting?.kid).toBe(previous?.kid)
    expect(waiting?.pendingKid).toBe(staged?.pendingKid)

    const activatedResult = await runScheduledMaintenance(env, NOW + JWKS_PROPAGATION_SECONDS)
    const activated = await getSigningKeyStatus(env)
    const activatedJwks = await getPublicJwks(env)

    expect(activatedResult.signingKeyRotated).toBe(true)
    expect(activated?.kid).toBe(staged?.pendingKid)
    expect(activated?.pendingKid).toBeNull()
    expect(activated?.pendingSince).toBeNull()
    expect(activated?.createdAt).toBe(NOW)
    expect(activatedJwks.keys.map((key) => key.kid)).toEqual(
      expect.arrayContaining([previous?.kid, activated?.kid]),
    )
  })

  it("serializes concurrent first-use signing-key initialization through D1", async () => {
    const [first, second] = await Promise.all([getPublicJwks(env), getPublicJwks(env)])
    const status = await getSigningKeyStatus(env)
    const persisted = await env.DB.prepare(
      "SELECT version FROM signing_key_state WHERE id = 1",
    ).first<{ version: number }>()

    expect(first.keys).toHaveLength(1)
    expect(second.keys).toHaveLength(1)
    expect(first.keys[0]?.kid).toBe(second.keys[0]?.kid)
    expect(status?.publishedKeyCount).toBe(1)
    expect(persisted?.version).toBe(1)
    expect(await env.KV.get("signing:active")).toBeNull()
    expect(await env.KV.get("signing:keys")).toBeNull()
  })

  it("reuses the per-isolate keyring without another D1 read", async () => {
    let prepares = 0
    const countingEnv = withPrepareCounter(env, () => {
      prepares += 1
    })

    await getPublicJwks(countingEnv)
    const firstLoadPrepares = prepares
    expect(firstLoadPrepares).toBeGreaterThan(0)

    await getPublicJwks(countingEnv)
    expect(prepares).toBe(firstLoadPrepares)
  })
})
