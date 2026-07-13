const DAY_SECONDS = 24 * 60 * 60

const REMOTE_ENVIRONMENTS = new Set(["staging", "production"])

function boundedInteger(
  name: string,
  raw: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  strict: boolean,
): number {
  if (raw !== undefined && /^\d+$/.test(raw)) {
    const parsed = Number(raw)
    if (Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum) return parsed
  }

  if (strict) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`)
  }
  return fallback
}

function booleanValue(
  name: string,
  raw: string | undefined,
  fallback: boolean,
  strict: boolean,
): boolean {
  if (raw === "true") return true
  if (raw === "false") return false
  if (strict) throw new Error(`${name} must be either true or false`)
  return fallback
}

function environmentName(raw: string): string {
  if (["local", "test", "staging", "production"].includes(raw)) return raw
  throw new Error("ENVIRONMENT must be local, test, staging, or production")
}

export type RuntimeConfig = {
  readonly environment: string
  readonly keyRotationIntervalSeconds: number
  readonly terminalDataRetentionDays: number
  readonly auditD1RetentionDays: number
  readonly maintenanceBatchSize: number
  readonly maintenanceLeaseSeconds: number
  readonly allowSelfSignup: boolean
}

/** Parse and bound every operator-controlled runtime value. Remote mistakes fail closed. */
export function getRuntimeConfig(env: Env): RuntimeConfig {
  const environment = environmentName(env.ENVIRONMENT)
  const strict = REMOTE_ENVIRONMENTS.has(environment)
  const values = env as unknown as Record<string, string | undefined>
  const auditD1RetentionDays = boundedInteger(
    "AUDIT_D1_RETENTION_DAYS",
    env.AUDIT_D1_RETENTION_DAYS,
    90,
    1,
    environment === "staging" ? 90 : 365,
    strict,
  )
  const requiredAuditRetention = environment === "staging" ? 90 : 365
  if (strict && auditD1RetentionDays !== requiredAuditRetention) {
    throw new Error(`AUDIT_D1_RETENTION_DAYS must be ${requiredAuditRetention} in ${environment}`)
  }
  return {
    environment,
    keyRotationIntervalSeconds: boundedInteger(
      "KEY_ROTATION_INTERVAL_SECONDS",
      env.KEY_ROTATION_INTERVAL_SECONDS,
      7 * DAY_SECONDS,
      DAY_SECONDS,
      365 * DAY_SECONDS,
      strict,
    ),
    terminalDataRetentionDays: boundedInteger(
      "TERMINAL_DATA_RETENTION_DAYS",
      env.TERMINAL_DATA_RETENTION_DAYS,
      30,
      1,
      3650,
      strict,
    ),
    auditD1RetentionDays,
    maintenanceBatchSize: boundedInteger(
      "MAINTENANCE_BATCH_SIZE",
      env.MAINTENANCE_BATCH_SIZE,
      100,
      1,
      100,
      strict,
    ),
    maintenanceLeaseSeconds: boundedInteger(
      "MAINTENANCE_LEASE_SECONDS",
      env.MAINTENANCE_LEASE_SECONDS,
      15 * 60,
      60,
      3600,
      strict,
    ),
    allowSelfSignup: booleanValue("ALLOW_SELF_SIGNUP", values["ALLOW_SELF_SIGNUP"], false, strict),
  }
}

export const SECONDS_PER_DAY = DAY_SECONDS
