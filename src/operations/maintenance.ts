import {
  getSigningKeyStatus,
  JWKS_PROPAGATION_SECONDS,
  rotateSigningKey,
} from "../tokens/key-rotation"
import { nowSeconds } from "../utils/time"
import { getRuntimeConfig, SECONDS_PER_DAY } from "./runtime-config"

const JOB_NAME = "scheduled-maintenance"
// Keep the whole invocation below D1's 50-query Free-plan budget. Running
// hourly provides 28,800 expired-audit-row deletions/day at the maximum batch size.
const MAX_AUDIT_DELETE_BATCHES_PER_RUN = 12
const MAX_CLEANUP_BATCHES_PER_TABLE = 2

export type MaintenanceResult = {
  readonly status: "completed" | "skipped"
  readonly signingKeyRotated: boolean
  readonly deletedAuditRows: number
  readonly deletedRows: Readonly<Record<string, number>>
  readonly auditBacklogRemaining: number
  readonly oldestEligibleAuditAt: number | null
}

async function acquireLease(
  env: Env,
  ownerToken: string,
  now: number,
  leaseSeconds: number,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `INSERT INTO maintenance_leases (job_name, owner_token, lease_until, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(job_name) DO UPDATE SET
       owner_token = excluded.owner_token,
       lease_until = excluded.lease_until,
       updated_at = excluded.updated_at
     WHERE maintenance_leases.lease_until <= ?`,
  )
    .bind(JOB_NAME, ownerToken, now + leaseSeconds, now, now)
    .run()
  return result.meta.changes === 1
}

async function releaseLease(env: Env, ownerToken: string): Promise<void> {
  await env.DB.prepare("DELETE FROM maintenance_leases WHERE job_name = ? AND owner_token = ?")
    .bind(JOB_NAME, ownerToken)
    .run()
}

async function rotateSigningKeyWhenDue(
  env: Env,
  now: number,
  intervalSeconds: number,
): Promise<boolean> {
  const status = await getSigningKeyStatus(env)
  if (status?.pendingKid !== null && status?.pendingKid !== undefined) {
    if (status.pendingSince === null || now - status.pendingSince < JWKS_PROPAGATION_SECONDS) {
      return false
    }
    await rotateSigningKey(env, now)
    return true
  }
  if (status !== null && now - status.createdAt < intervalSeconds) {
    return false
  }
  await rotateSigningKey(env, now)
  return true
}

async function deleteExpiredAuditLogs(
  env: Env,
  cutoff: number,
  batchSize: number,
): Promise<number> {
  let deleted = 0
  for (let batch = 0; batch < MAX_AUDIT_DELETE_BATCHES_PER_RUN; batch += 1) {
    const result = await env.DB.prepare(
      `DELETE FROM audit_logs
       WHERE id IN (
         SELECT id
         FROM audit_logs
         WHERE created_at < ?
         ORDER BY created_at ASC, id ASC
         LIMIT ?
       )`,
    )
      .bind(cutoff, batchSize)
      .run()
    deleted += result.meta.changes
    if (result.meta.changes < batchSize) break
  }
  return deleted
}

async function auditBacklog(
  env: Env,
  cutoff: number,
): Promise<{ readonly count: number; readonly oldest: number | null }> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS count, MIN(created_at) AS oldest FROM audit_logs WHERE created_at < ?",
  )
    .bind(cutoff)
    .first<{ count: number; oldest: number | null }>()
  return { count: row?.count ?? 0, oldest: row?.oldest ?? null }
}

type CleanupStatement = {
  readonly name: string
  readonly sql: string
  readonly values: readonly unknown[]
}

type CleanupBranch = {
  readonly terminalColumn: string
  readonly predicate: string
  readonly values: readonly unknown[]
}

/**
 * Build one bounded delete from independently indexed terminal-state branches.
 * Each branch contributes at most one batch of candidates; de-duplication and
 * the final limit keep the DELETE itself bounded even when a row matches more
 * than one branch.
 */
function boundedCleanupStatement(
  name: string,
  table: string,
  keyColumn: string,
  branches: readonly CleanupBranch[],
  batchSize: number,
): CleanupStatement {
  const candidates = branches
    .map(
      (branch) => `SELECT row_key, terminal_at FROM (
        SELECT ${keyColumn} AS row_key, ${branch.terminalColumn} AS terminal_at
        FROM ${table}
        WHERE ${branch.predicate}
        ORDER BY ${branch.terminalColumn} ASC, ${keyColumn} ASC
        LIMIT ?
      )`,
    )
    .join("\nUNION ALL\n")
  return {
    name,
    sql: `WITH candidates(row_key, terminal_at) AS (
      ${candidates}
    ), bounded(row_key) AS (
      SELECT row_key
      FROM candidates
      GROUP BY row_key
      ORDER BY MIN(terminal_at) ASC, row_key ASC
      LIMIT ?
    )
    DELETE FROM ${table} WHERE ${keyColumn} IN (SELECT row_key FROM bounded)`,
    values: [...branches.flatMap((branch) => [...branch.values, batchSize]), batchSize],
  }
}

async function cleanupTerminalRows(
  env: Env,
  cutoff: number,
  batchSize: number,
  now: number,
): Promise<Readonly<Record<string, number>>> {
  const statements: readonly CleanupStatement[] = [
    boundedCleanupStatement(
      "sessions",
      "sessions",
      "id",
      [
        { terminalColumn: "expires_at", predicate: "expires_at < ?", values: [cutoff] },
        {
          terminalColumn: "revoked_at",
          predicate: "revoked_at IS NOT NULL AND revoked_at < ?",
          values: [cutoff],
        },
      ],
      batchSize,
    ),
    boundedCleanupStatement(
      "refresh_tokens",
      "refresh_tokens",
      "id",
      [
        { terminalColumn: "expires_at", predicate: "expires_at < ?", values: [cutoff] },
        {
          terminalColumn: "revoked_at",
          predicate: "revoked_at IS NOT NULL AND revoked_at < ?",
          values: [cutoff],
        },
      ],
      batchSize,
    ),
    boundedCleanupStatement(
      "authorization_grants",
      "authorization_grants",
      "id",
      [{ terminalColumn: "created_at", predicate: "created_at < ?", values: [cutoff] }],
      batchSize,
    ),
    boundedCleanupStatement(
      "device_authorization_sessions",
      "device_authorization_sessions",
      "id",
      [
        { terminalColumn: "expires_at", predicate: "expires_at < ?", values: [cutoff] },
        {
          terminalColumn: "created_at",
          predicate: "status = 'denied' AND created_at < ?",
          values: [cutoff],
        },
        {
          terminalColumn: "created_at",
          predicate: "status = 'expired' AND created_at < ?",
          values: [cutoff],
        },
        {
          terminalColumn: "created_at",
          predicate: "status = 'consumed' AND created_at < ?",
          values: [cutoff],
        },
      ],
      batchSize,
    ),
    boundedCleanupStatement(
      "email_verifications",
      "email_verifications",
      "id",
      [
        { terminalColumn: "expires_at", predicate: "expires_at < ?", values: [cutoff] },
        {
          terminalColumn: "consumed_at",
          predicate: "consumed_at IS NOT NULL AND consumed_at < ?",
          values: [cutoff],
        },
      ],
      batchSize,
    ),
    boundedCleanupStatement(
      "password_reset_tokens",
      "password_reset_tokens",
      "id",
      [
        { terminalColumn: "expires_at", predicate: "expires_at < ?", values: [cutoff] },
        {
          terminalColumn: "consumed_at",
          predicate: "consumed_at IS NOT NULL AND consumed_at < ?",
          values: [cutoff],
        },
      ],
      batchSize,
    ),
    boundedCleanupStatement(
      "reauth_continuations",
      "reauth_continuations",
      "token_hash",
      [
        { terminalColumn: "expires_at", predicate: "expires_at < ?", values: [now] },
        {
          terminalColumn: "consumed_at",
          predicate: "consumed_at IS NOT NULL",
          values: [],
        },
      ],
      batchSize,
    ),
  ]

  const results: Record<string, number> = {}
  for (const statement of statements) {
    let deleted = 0
    for (let batch = 0; batch < MAX_CLEANUP_BATCHES_PER_TABLE; batch += 1) {
      const result = await env.DB.prepare(statement.sql)
        .bind(...statement.values)
        .run()
      deleted += result.meta.changes
      if (result.meta.changes < batchSize) break
    }
    results[statement.name] = deleted
  }
  return results
}

/** Execute the idempotent scheduled (normally hourly) pipeline under a D1-backed lease. */
export async function runScheduledMaintenance(
  env: Env,
  scheduledAt = nowSeconds(),
): Promise<MaintenanceResult> {
  const config = getRuntimeConfig(env)
  const ownerToken = crypto.randomUUID()
  const acquired = await acquireLease(env, ownerToken, nowSeconds(), config.maintenanceLeaseSeconds)
  if (!acquired) {
    return {
      status: "skipped",
      signingKeyRotated: false,
      deletedAuditRows: 0,
      deletedRows: {},
      auditBacklogRemaining: 0,
      oldestEligibleAuditAt: null,
    }
  }

  try {
    const signingKeyRotated = await rotateSigningKeyWhenDue(
      env,
      scheduledAt,
      config.keyRotationIntervalSeconds,
    )
    const auditCutoff = scheduledAt - config.auditD1RetentionDays * SECONDS_PER_DAY
    const deletedAuditRows = await deleteExpiredAuditLogs(
      env,
      auditCutoff,
      config.maintenanceBatchSize,
    )
    const deletedRows = await cleanupTerminalRows(
      env,
      scheduledAt - config.terminalDataRetentionDays * SECONDS_PER_DAY,
      config.maintenanceBatchSize,
      scheduledAt,
    )
    const backlog = await auditBacklog(env, auditCutoff)
    if (backlog.count > 0) {
      console.warn("maintenance.audit_backlog", {
        count: backlog.count,
        oldestEligibleAuditAt: backlog.oldest,
      })
    }
    return {
      status: "completed",
      signingKeyRotated,
      deletedAuditRows,
      deletedRows,
      auditBacklogRemaining: backlog.count,
      oldestEligibleAuditAt: backlog.oldest,
    }
  } finally {
    await releaseLease(env, ownerToken)
  }
}
