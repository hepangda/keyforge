import {
  getSigningKeyStatus,
  JWKS_PROPAGATION_SECONDS,
  rotateSigningKey,
} from "../tokens/key-rotation"
import { nowSeconds } from "../utils/time"
import { getRuntimeConfig, SECONDS_PER_DAY } from "./runtime-config"

const JOB_NAME = "scheduled-maintenance"
const ARCHIVE_SCHEMA_VERSION = 2
const PRUNABLE_ARCHIVE_SCHEMA_VERSIONS = [1, ARCHIVE_SCHEMA_VERSION] as const
// Keep the whole invocation below D1's 50-query Free-plan budget. Running
// hourly provides 28,800 archived rows/day at the maximum batch size.
const MAX_ARCHIVE_BATCHES_PER_RUN = 12
const MAX_ARCHIVE_LIST_PAGES_PER_RUN = 10
const MAX_CLEANUP_BATCHES_PER_TABLE = 2
const ARCHIVE_CURSOR_KEY = "audit_archive_prune_cursor"

type AuditArchiveRow = {
  readonly id: string
  readonly event_type: string
  readonly actor_user_id: string | null
  readonly actor_client_id: string | null
  readonly user_id: string | null
  readonly client_id: string | null
  readonly resource_uri: string | null
  readonly request_id: string | null
  readonly ip_hash: string | null
  readonly user_agent_hash: string | null
  readonly scope: string | null
  readonly success: number | null
  readonly detail: string | null
  readonly metadata_json: string | null
  readonly created_at: number
}

export type MaintenanceResult = {
  readonly status: "completed" | "skipped"
  readonly signingKeyRotated: boolean
  readonly archivedAuditRows: number
  readonly deletedArchiveObjects: number
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

function safeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_")
}

function archiveObjectKey(env: Env, rows: readonly AuditArchiveRow[]): string {
  const first = rows[0]
  const last = rows.at(-1)
  if (first === undefined || last === undefined) {
    throw new Error("cannot construct an audit archive key for an empty batch")
  }
  const date = new Date(first.created_at * 1000).toISOString().slice(0, 10).replaceAll("-", "/")
  return [
    "audit",
    `v${ARCHIVE_SCHEMA_VERSION}`,
    safeSegment(env.ENVIRONMENT),
    date,
    `${first.created_at}-${last.created_at}-${safeSegment(first.id)}-${safeSegment(last.id)}.json`,
  ].join("/")
}

async function deleteArchivedRows(env: Env, rows: readonly AuditArchiveRow[]): Promise<number> {
  if (rows.length === 0) return 0
  const placeholders = rows.map(() => "?").join(",")
  const result = await env.DB.prepare(`DELETE FROM audit_logs WHERE id IN (${placeholders})`)
    .bind(...rows.map((row) => row.id))
    .run()
  return result.meta.changes
}

async function archiveAuditLogs(
  env: Env,
  cutoff: number,
  batchSize: number,
  archivedAt: number,
): Promise<number> {
  let archived = 0
  for (let batch = 0; batch < MAX_ARCHIVE_BATCHES_PER_RUN; batch += 1) {
    const result = await env.DB.prepare(
      `SELECT id, event_type, actor_user_id, actor_client_id, user_id, client_id,
              resource_uri, request_id, ip_hash, user_agent_hash, scope, success,
              detail, metadata_json, created_at
       FROM audit_logs
       WHERE created_at < ?
       ORDER BY created_at ASC, id ASC
       LIMIT ?`,
    )
      .bind(cutoff, batchSize)
      .all<AuditArchiveRow>()
    if (result.results.length === 0) break

    // Keep every object in one UTC-date partition even when a query crosses
    // midnight; later iterations pick up the remaining rows.
    const firstDate = new Date((result.results[0]?.created_at ?? 0) * 1000)
      .toISOString()
      .slice(0, 10)
    const rows = result.results.filter(
      (row) => new Date(row.created_at * 1000).toISOString().slice(0, 10) === firstDate,
    )
    const key = archiveObjectKey(env, rows)
    const payload = JSON.stringify({
      schema_version: ARCHIVE_SCHEMA_VERSION,
      environment: env.ENVIRONMENT,
      archived_at: archivedAt,
      row_count: rows.length,
      records: rows,
    })
    await env.ARCHIVE.put(key, payload, {
      httpMetadata: { contentType: "application/json; charset=utf-8" },
      customMetadata: {
        schemaVersion: String(ARCHIVE_SCHEMA_VERSION),
        rowCount: String(rows.length),
        firstCreatedAt: String(rows[0]?.created_at ?? ""),
        lastCreatedAt: String(rows.at(-1)?.created_at ?? ""),
      },
    })
    archived += await deleteArchivedRows(env, rows)
    if (result.results.length < batchSize) break
  }
  return archived
}

function archiveCursorKey(schemaVersion: number): string {
  return schemaVersion === 1 ? ARCHIVE_CURSOR_KEY : `${ARCHIVE_CURSOR_KEY}_v${schemaVersion}`
}

async function pruneAuditArchiveVersion(
  env: Env,
  cutoffMilliseconds: number,
  schemaVersion: number,
  pageBudget: number,
): Promise<number> {
  const prefix = `audit/v${schemaVersion}/${safeSegment(env.ENVIRONMENT)}/`
  const cursorKey = archiveCursorKey(schemaVersion)
  const saved = await env.DB.prepare("SELECT value FROM maintenance_state WHERE key = ?")
    .bind(cursorKey)
    .first<{ value: string }>()
  let cursor = saved?.value || undefined
  let deleted = 0
  for (let page = 0; page < pageBudget; page += 1) {
    const listed = await env.ARCHIVE.list(
      cursor === undefined ? { prefix, limit: 1000 } : { prefix, cursor, limit: 1000 },
    )
    const expired = listed.objects
      .filter((object) => object.uploaded.getTime() < cutoffMilliseconds)
      .map((object) => object.key)
    if (expired.length > 0) {
      await env.ARCHIVE.delete(expired)
      deleted += expired.length
    }
    if (!listed.truncated) {
      cursor = undefined
      break
    }
    cursor = listed.cursor
  }
  if (cursor === undefined) {
    await env.DB.prepare("DELETE FROM maintenance_state WHERE key = ?").bind(cursorKey).run()
  } else {
    await env.DB.prepare(
      `INSERT INTO maintenance_state (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
      .bind(cursorKey, cursor, nowSeconds())
      .run()
  }
  return deleted
}

async function pruneAuditArchive(env: Env, cutoffMilliseconds: number): Promise<number> {
  // Split the fixed list-page budget so legacy v1 archives and actor-aware v2
  // archives both continue aging out during a long-running migration period.
  const pageBudget = Math.max(
    1,
    Math.floor(MAX_ARCHIVE_LIST_PAGES_PER_RUN / PRUNABLE_ARCHIVE_SCHEMA_VERSIONS.length),
  )
  let deleted = 0
  for (const schemaVersion of PRUNABLE_ARCHIVE_SCHEMA_VERSIONS) {
    deleted += await pruneAuditArchiveVersion(env, cutoffMilliseconds, schemaVersion, pageBudget)
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
      archivedAuditRows: 0,
      deletedArchiveObjects: 0,
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
    const archivedAuditRows = await archiveAuditLogs(
      env,
      auditCutoff,
      config.maintenanceBatchSize,
      scheduledAt,
    )
    const deletedArchiveObjects = await pruneAuditArchive(
      env,
      (scheduledAt - config.auditArchiveRetentionDays * SECONDS_PER_DAY) * 1000,
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
      archivedAuditRows,
      deletedArchiveObjects,
      deletedRows,
      auditBacklogRemaining: backlog.count,
      oldestEligibleAuditAt: backlog.oldest,
    }
  } finally {
    await releaseLease(env, ownerToken)
  }
}
