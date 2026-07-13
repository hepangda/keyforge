import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

type PlanCase = {
  readonly name: string
  readonly table: string
  readonly index: string
  readonly sql: string
  readonly bindings: readonly (string | number)[]
}

const CUTOFF = 2_000_000_000
const cases: readonly PlanCase[] = [
  {
    name: "audit retention",
    table: "audit_logs",
    index: "idx_audit_created_id",
    sql: `SELECT id FROM audit_logs
          WHERE created_at < ? ORDER BY created_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "session expiry",
    table: "sessions",
    index: "idx_sessions_cleanup_expires",
    sql: "SELECT id FROM sessions WHERE expires_at < ? ORDER BY expires_at, id LIMIT ?",
    bindings: [CUTOFF, 100],
  },
  {
    name: "session revocation",
    table: "sessions",
    index: "idx_sessions_cleanup_revoked",
    sql: `SELECT id FROM sessions
          WHERE revoked_at IS NOT NULL AND revoked_at < ?
          ORDER BY revoked_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "refresh expiry",
    table: "refresh_tokens",
    index: "idx_refresh_cleanup_expires",
    sql: `SELECT id FROM refresh_tokens
          WHERE expires_at < ? ORDER BY expires_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "refresh revocation",
    table: "refresh_tokens",
    index: "idx_refresh_cleanup_revoked",
    sql: `SELECT id FROM refresh_tokens
          WHERE revoked_at IS NOT NULL AND revoked_at < ?
          ORDER BY revoked_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "grant age",
    table: "authorization_grants",
    index: "idx_grants_cleanup_created",
    sql: `SELECT id FROM authorization_grants
          WHERE created_at < ? ORDER BY created_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "device expiry",
    table: "device_authorization_sessions",
    index: "idx_device_cleanup_expires",
    sql: `SELECT id FROM device_authorization_sessions
          WHERE expires_at < ? ORDER BY expires_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "device terminal status age",
    table: "device_authorization_sessions",
    index: "idx_device_cleanup_status_created",
    sql: `SELECT id FROM device_authorization_sessions
          WHERE status = ? AND created_at < ? ORDER BY created_at, id LIMIT ?`,
    bindings: ["consumed", CUTOFF, 100],
  },
  {
    name: "device client active cap",
    table: "device_authorization_sessions",
    index: "idx_device_client_active",
    sql: `SELECT COUNT(*) FROM device_authorization_sessions
          WHERE client_id = ? AND status IN ('pending', 'approved') AND expires_at > ?`,
    bindings: ["pangda_cli", CUTOFF],
  },
  {
    name: "email verification expiry",
    table: "email_verifications",
    index: "idx_email_verification_cleanup_expires",
    sql: `SELECT id FROM email_verifications
          WHERE expires_at < ? ORDER BY expires_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "email verification consumption",
    table: "email_verifications",
    index: "idx_email_verification_cleanup_consumed",
    sql: `SELECT id FROM email_verifications
          WHERE consumed_at IS NOT NULL AND consumed_at < ?
          ORDER BY consumed_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "password reset expiry",
    table: "password_reset_tokens",
    index: "idx_password_reset_cleanup_expires",
    sql: `SELECT id FROM password_reset_tokens
          WHERE expires_at < ? ORDER BY expires_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "password reset consumption",
    table: "password_reset_tokens",
    index: "idx_password_reset_cleanup_consumed",
    sql: `SELECT id FROM password_reset_tokens
          WHERE consumed_at IS NOT NULL AND consumed_at < ?
          ORDER BY consumed_at, id LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "reauth expiry",
    table: "reauth_continuations",
    index: "idx_reauth_cleanup_expires",
    sql: `SELECT token_hash FROM reauth_continuations
          WHERE expires_at < ? ORDER BY expires_at, token_hash LIMIT ?`,
    bindings: [CUTOFF, 100],
  },
  {
    name: "reauth consumption",
    table: "reauth_continuations",
    index: "idx_reauth_cleanup_consumed",
    sql: `SELECT token_hash FROM reauth_continuations
          WHERE consumed_at IS NOT NULL ORDER BY consumed_at, token_hash LIMIT ?`,
    bindings: [100],
  },
]

describe("migration 0011 cleanup indexes", () => {
  for (const planCase of cases) {
    it(`uses ${planCase.name} index`, async () => {
      const plan = await env.DB.prepare(`EXPLAIN QUERY PLAN ${planCase.sql}`)
        .bind(...planCase.bindings)
        .all<{ detail: string }>()
      const details = plan.results.map((row) => row.detail).join("\n")

      expect(details).toContain(planCase.index)
      expect(details).not.toContain(`SCAN ${planCase.table}`)
    })
  }
})
