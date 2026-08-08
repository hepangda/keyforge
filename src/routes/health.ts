import { Hono } from "hono"
import { getRuntimeConfig } from "../operations/runtime-config"
import { isYoloEnabled } from "../operations/yolo"
import { timingSafeEqualString } from "../security/crypto"
import {
  assertLegacySigningKeyCleanupComplete,
  getActiveSigningKey,
  getPublicJwks,
} from "../tokens/key-rotation"
import type { AppBindings } from "../types/app"

export const health = new Hono<AppBindings>()

health.get("/health", (c) =>
  c.json({ status: "ok", service: "keyforge", time: new Date().toISOString() }),
)

type DependencyCheck = { readonly status: "ok" | "failed" }
type ReadinessAccess = "allowed" | "unauthorized" | "misconfigured"
const READINESS_TOKEN_PATTERN = /^[A-Za-z0-9._~-]{32,256}$/

export function readinessAccessStatus(
  environment: string,
  configuredToken: string | undefined,
  authorization: string | undefined,
): ReadinessAccess {
  if (environment === "local" || environment === "test") return "allowed"
  if (configuredToken === undefined || !READINESS_TOKEN_PATTERN.test(configuredToken)) {
    return "misconfigured"
  }
  const match = authorization?.match(/^Bearer ([A-Za-z0-9._~-]{32,256})$/i)
  return match?.[1] !== undefined && timingSafeEqualString(configuredToken, match[1])
    ? "allowed"
    : "unauthorized"
}

const REQUIRED_TABLES = [
  "users",
  "groups",
  "password_credentials",
  "webauthn_credentials",
  "oauth_clients",
  "oauth_resources",
  "oauth_client_permission_groups",
  "oauth_resource_permission_groups",
  "group_membership_requests",
  "sessions",
  "refresh_tokens",
  "device_authorization_sessions",
  "bootstrap_state",
  "reauth_continuations",
  "signing_key_state",
  "maintenance_state",
  "maintenance_leases",
] as const

const REQUIRED_INDEXES = [
  "idx_audit_created_id",
  "idx_sessions_cleanup_expires",
  "idx_sessions_cleanup_revoked",
  "idx_refresh_cleanup_expires",
  "idx_refresh_cleanup_revoked",
  "idx_password_reset_cleanup_expires",
  "idx_password_reset_cleanup_consumed",
  "idx_email_verification_cleanup_expires",
  "idx_email_verification_cleanup_consumed",
  "idx_grants_cleanup_created",
  "idx_device_cleanup_expires",
  "idx_device_cleanup_status_created",
  "idx_device_client_active",
  "idx_reauth_cleanup_expires",
  "idx_reauth_cleanup_consumed",
  "idx_audit_actor_user_created",
  "idx_audit_actor_client_created",
  "idx_users_alias_canonical",
  "idx_password_credentials_user",
  "idx_oauth_client_permission_groups_group",
  "idx_oauth_resource_permission_groups_group",
  "idx_group_membership_requests_group",
  "idx_group_membership_requests_user",
] as const

function requireNonEmpty(value: unknown, name: string, minimumLength = 1): void {
  if (typeof value !== "string" || value.trim().length < minimumLength) {
    throw new Error(`${name} is not configured`)
  }
}

async function checkDatabaseSchema(db: D1Database): Promise<void> {
  const tableRows = await db
    .prepare(
      `SELECT name FROM sqlite_master
       WHERE type = 'table' AND name IN (${REQUIRED_TABLES.map(() => "?").join(", ")})`,
    )
    .bind(...REQUIRED_TABLES)
    .all<{ name: string }>()
  const presentTables = new Set(tableRows.results.map((row) => row.name))
  const missingTables = REQUIRED_TABLES.filter((name) => !presentTables.has(name))
  if (missingTables.length > 0) {
    throw new Error(`required database tables are missing: ${missingTables.join(", ")}`)
  }

  const invariants = await db
    .prepare(
      `SELECT
         EXISTS(SELECT 1 FROM pragma_table_info('users')
                WHERE name = 'security_version') AS user_security_version_column,
         EXISTS(SELECT 1 FROM pragma_table_info('users')
                WHERE name = 'alias') AS user_alias_column,
         NOT EXISTS(SELECT 1 FROM pragma_table_info('users')
                WHERE name = 'user_type') AS user_type_removed,
         EXISTS(SELECT 1 FROM pragma_table_info('oauth_clients')
                WHERE name = 'post_logout_redirect_uris_json') AS logout_column,
         EXISTS(SELECT 1 FROM pragma_table_info('refresh_tokens')
                WHERE name = 'auth_time') AS refresh_auth_time_column,
         EXISTS(SELECT 1 FROM pragma_table_info('device_authorization_sessions')
                WHERE name = 'session_id') AS device_session_column,
         EXISTS(SELECT 1 FROM pragma_table_info('device_authorization_sessions')
                WHERE name = 'auth_time') AS device_auth_time_column,
         EXISTS(SELECT 1 FROM pragma_table_info('audit_logs')
                WHERE name = 'actor_user_id') AS audit_actor_user_column,
         EXISTS(SELECT 1 FROM pragma_table_info('audit_logs')
                WHERE name = 'actor_client_id') AS audit_actor_client_column,
         EXISTS(SELECT 1 FROM pragma_index_list('users')
                WHERE name = 'idx_users_email_canonical' AND [unique] = 1) AS canonical_email_index,
         EXISTS(SELECT 1 FROM pragma_index_list('users')
                WHERE name = 'idx_users_alias_canonical' AND [unique] = 1) AS canonical_alias_index,
         EXISTS(SELECT 1 FROM pragma_index_list('groups')
                WHERE name = 'idx_groups_name_canonical' AND [unique] = 1) AS canonical_group_index,
         EXISTS(SELECT 1 FROM groups WHERE name = 'all') AS all_group,
         EXISTS(SELECT 1 FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'add_all_group_membership_after_user_insert') AS all_group_trigger,
         EXISTS(SELECT 1 FROM groups WHERE name = 'admins') AS admin_group,
         EXISTS(SELECT 1 FROM oauth_resources
                WHERE resource_uri = 'https://admin.pangda.app') AS admin_resource,
         EXISTS(SELECT 1 FROM oauth_clients WHERE client_id = 'pangda_admin') AS admin_client`,
    )
    .first<Record<string, number>>()
  if (invariants === null || Object.values(invariants).some((value) => value !== 1)) {
    throw new Error("required database columns, indexes, or seed catalog are missing")
  }

  const indexRows = await db
    .prepare(
      `SELECT name FROM sqlite_master
       WHERE type = 'index' AND name IN (${REQUIRED_INDEXES.map(() => "?").join(", ")})`,
    )
    .bind(...REQUIRED_INDEXES)
    .all<{ name: string }>()
  const presentIndexes = new Set(indexRows.results.map((row) => row.name))
  const missingIndexes = REQUIRED_INDEXES.filter((name) => !presentIndexes.has(name))
  if (missingIndexes.length > 0) {
    throw new Error(`required database indexes are missing: ${missingIndexes.join(", ")}`)
  }
}

function checkBindings(env: Env): void {
  const bindings = env as unknown as Record<string, unknown>
  const required = [
    "DB",
    "KV",
    "AUDIT_QUEUE",
    "EMAIL_QUEUE",
    "AUTHORIZATION_CODE",
    "ONE_TIME_TOKEN",
    "WEBAUTHN_CHALLENGE",
    "REFRESH_TOKEN_FAMILY",
    "RATE_LIMIT",
  ]
  const missing = required.filter((name) => bindings[name] === undefined || bindings[name] === null)
  if (missing.length > 0) throw new Error(`required bindings are missing: ${missing.join(", ")}`)
}

function checkRuntimeConfiguration(env: Env): void {
  const config = getRuntimeConfig(env)
  const values = env as unknown as Record<string, unknown>
  // YOLO mode drops the remote configuration requirements along with every
  // other validation, so a half-configured dev Worker still reports ready.
  const remote =
    (config.environment === "dev" || config.environment === "production") && !isYoloEnabled(env)

  if (!["resend", "console", "test"].includes(env.EMAIL_DELIVERY_MODE)) {
    throw new Error("EMAIL_DELIVERY_MODE is invalid")
  }
  if (remote && env.EMAIL_DELIVERY_MODE !== "resend") {
    throw new Error("remote environments must use EMAIL_DELIVERY_MODE=resend")
  }
  if (env.EMAIL_DELIVERY_MODE === "resend") {
    requireNonEmpty(values["RESEND_API_KEY"], "RESEND_API_KEY", 16)
    requireNonEmpty(values["EMAIL_FROM"], "EMAIL_FROM")
    if (!String(values["EMAIL_FROM"]).includes("@")) throw new Error("EMAIL_FROM is invalid")
  }
  if (remote) requireNonEmpty(values["REQUEST_HASH_SECRET"], "REQUEST_HASH_SECRET", 32)
  if (
    remote &&
    (typeof values["READINESS_PROBE_TOKEN"] !== "string" ||
      !READINESS_TOKEN_PATTERN.test(values["READINESS_PROBE_TOKEN"]))
  ) {
    throw new Error("READINESS_PROBE_TOKEN is not configured or contains invalid characters")
  }
}

/** Readiness probe: validates every dependency needed for safe token service. */
health.get("/health/ready", async (c) => {
  const access = isYoloEnabled(c.env)
    ? "allowed"
    : readinessAccessStatus(
        c.env.ENVIRONMENT,
        c.env.READINESS_PROBE_TOKEN,
        c.req.header("authorization"),
      )
  if (access === "misconfigured") {
    console.error("health.readiness_probe_token_missing", c.get("requestId"))
    return c.json({ status: "unavailable" }, 503)
  }
  if (access === "unauthorized") {
    c.header("www-authenticate", 'Bearer realm="keyforge-readiness"')
    return c.json({ error: "unauthorized" }, 401)
  }
  const probes: ReadonlyArray<readonly [string, () => Promise<unknown>]> = [
    ["bindings", async () => checkBindings(c.env)],
    ["runtime_configuration", async () => checkRuntimeConfiguration(c.env)],
    ["database", () => checkDatabaseSchema(c.env.DB)],
    [
      "signing_keys",
      async () => {
        const active = await getActiveSigningKey(c.env)
        const jwks = await getPublicJwks(c.env)
        if (!jwks.keys.some((key) => key.kid === active.kid)) {
          throw new Error("active signing key is not published")
        }
        await assertLegacySigningKeyCleanupComplete(c.env)
      },
    ],
    ["audit_queue", () => c.env.AUDIT_QUEUE.metrics()],
    ["email_queue", () => c.env.EMAIL_QUEUE.metrics()],
    [
      "durable_objects",
      async () => {
        const response = await c.env.RATE_LIMIT.getByName("readiness").ping()
        if (response !== "ok") throw new Error("unexpected durable object response")
      },
    ],
  ]

  const settled = await Promise.allSettled(probes.map(([, probe]) => probe()))
  const checks: Record<string, DependencyCheck> = {}
  let ready = true
  for (const [index, result] of settled.entries()) {
    const name = probes[index]?.[0] ?? `dependency_${index}`
    if (result.status === "fulfilled") {
      checks[name] = { status: "ok" }
    } else {
      ready = false
      checks[name] = { status: "failed" }
      console.error("health.dependency_failed", c.get("requestId"), name, result.reason)
    }
  }
  return c.json({ status: ready ? "ready" : "unavailable", checks }, ready ? 200 : 503)
})
