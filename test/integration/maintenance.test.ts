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
  for (const version of [1, 2]) {
    const archived = await env.ARCHIVE.list({ prefix: `audit/v${version}/local/` })
    if (archived.objects.length > 0) {
      await env.ARCHIVE.delete(archived.objects.map((object) => object.key))
    }
  }
})

describe("scheduled maintenance", () => {
  it("rotates signing keys, archives old audit rows, and removes terminal data", async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users
          (id, email, email_verified, name, user_type, disabled, created_at, updated_at)
         VALUES (?, ?, 1, ?, 'internal', 0, ?, ?)`,
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
        `INSERT INTO audit_logs
           (id, event_type, actor_user_id, actor_client_id, detail, created_at)
         VALUES (?, 'user.logout', 'usr_archive_actor', 'svc_archive_actor', 'old row', ?)`,
      ).bind("aud_maintenance_old", NOW - 91 * DAY),
      env.DB.prepare(
        `INSERT INTO audit_logs (id, event_type, detail, created_at)
         VALUES (?, 'user.logout', 'fresh row', ?)`,
      ).bind("aud_maintenance_fresh", NOW),
    ])

    const result = await runScheduledMaintenance(env, NOW)

    expect(result.status).toBe("completed")
    expect(result.signingKeyRotated).toBe(true)
    expect(result.archivedAuditRows).toBe(1)
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
      await env.DB.prepare("SELECT id FROM audit_logs WHERE id = 'aud_maintenance_old'").first(),
    ).toBeNull()
    expect(
      await env.DB.prepare("SELECT id FROM audit_logs WHERE id = 'aud_maintenance_fresh'").first(),
    ).not.toBeNull()

    const archived = await env.ARCHIVE.list({ prefix: "audit/v2/local/" })
    expect(archived.objects).toHaveLength(1)
    const object = await env.ARCHIVE.get(archived.objects[0]?.key ?? "")
    const payload = await object?.json<{
      row_count: number
      schema_version: number
      records: Array<{ id: string; actor_user_id: string; actor_client_id: string }>
    }>()
    expect(payload?.row_count).toBe(1)
    expect(payload?.schema_version).toBe(2)
    expect(payload?.records[0]?.id).toBe("aud_maintenance_old")
    expect(payload?.records[0]?.actor_user_id).toBe("usr_archive_actor")
    expect(payload?.records[0]?.actor_client_id).toBe("svc_archive_actor")
  })

  it("continues pruning legacy v1 and actor-aware v2 audit archives", async () => {
    const legacyKey = "audit/v1/local/2020/01/01/legacy.json"
    const currentKey = "audit/v2/local/2020/01/01/current.json"
    await Promise.all([
      env.ARCHIVE.put(legacyKey, JSON.stringify({ schema_version: 1 })),
      env.ARCHIVE.put(currentKey, JSON.stringify({ schema_version: 2 })),
    ])

    const result = await runScheduledMaintenance(env, Math.floor(Date.now() / 1000) + 8 * 365 * DAY)

    expect(result.deletedArchiveObjects).toBe(2)
    expect(await env.ARCHIVE.head(legacyKey)).toBeNull()
    expect(await env.ARCHIVE.head(currentKey)).toBeNull()
  })

  it("removes non-expired rows through each secondary terminal-state branch", async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users
          (id, email, email_verified, name, user_type, disabled, created_at, updated_at)
         VALUES ('usr_maintenance_test', 'maintenance@example.test', 1, 'Maintenance Test',
                 'internal', 0, ?, ?)`,
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
})
