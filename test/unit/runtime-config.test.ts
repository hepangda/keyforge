import { describe, expect, it } from "vitest"
import { getRuntimeConfig } from "../../src/operations/runtime-config"

function configEnv(overrides: Record<string, string> = {}): Env {
  return {
    ENVIRONMENT: "test",
    KEY_ROTATION_INTERVAL_SECONDS: "604800",
    TERMINAL_DATA_RETENTION_DAYS: "30",
    AUDIT_D1_RETENTION_DAYS: "90",
    AUDIT_ARCHIVE_RETENTION_DAYS: "2555",
    MAINTENANCE_BATCH_SIZE: "100",
    MAINTENANCE_LEASE_SECONDS: "900",
    ALLOW_SELF_SIGNUP: "false",
    ...overrides,
  } as unknown as Env
}

describe("runtime maintenance configuration", () => {
  it("accepts bounded operator values", () => {
    const config = getRuntimeConfig(
      configEnv({
        KEY_ROTATION_INTERVAL_SECONDS: "86400",
        TERMINAL_DATA_RETENTION_DAYS: "7",
        AUDIT_D1_RETENTION_DAYS: "31",
        AUDIT_ARCHIVE_RETENTION_DAYS: "365",
        MAINTENANCE_BATCH_SIZE: "25",
        MAINTENANCE_LEASE_SECONDS: "120",
        ALLOW_SELF_SIGNUP: "true",
      }),
    )

    expect(config).toMatchObject({
      keyRotationIntervalSeconds: 86400,
      terminalDataRetentionDays: 7,
      auditD1RetentionDays: 31,
      auditArchiveRetentionDays: 365,
      maintenanceBatchSize: 25,
      maintenanceLeaseSeconds: 120,
      allowSelfSignup: true,
    })
  })

  it("falls back safely for malformed and out-of-range values", () => {
    const config = getRuntimeConfig(
      configEnv({
        KEY_ROTATION_INTERVAL_SECONDS: "0",
        TERMINAL_DATA_RETENTION_DAYS: "not-a-number",
        AUDIT_D1_RETENTION_DAYS: "-1",
        AUDIT_ARCHIVE_RETENTION_DAYS: "999999",
        MAINTENANCE_BATCH_SIZE: "101",
        MAINTENANCE_LEASE_SECONDS: "1",
      }),
    )

    expect(config).toMatchObject({
      keyRotationIntervalSeconds: 604800,
      terminalDataRetentionDays: 30,
      auditD1RetentionDays: 90,
      auditArchiveRetentionDays: 2555,
      maintenanceBatchSize: 100,
      maintenanceLeaseSeconds: 900,
      allowSelfSignup: false,
    })
  })

  it("fails closed for malformed remote values", () => {
    expect(() =>
      getRuntimeConfig(
        configEnv({
          ENVIRONMENT: "production",
          MAINTENANCE_BATCH_SIZE: "101",
        }),
      ),
    ).toThrow(/MAINTENANCE_BATCH_SIZE/)

    expect(() =>
      getRuntimeConfig(
        configEnv({
          ENVIRONMENT: "staging",
          ALLOW_SELF_SIGNUP: "sometimes",
        }),
      ),
    ).toThrow(/ALLOW_SELF_SIGNUP/)
  })

  it("rejects unknown environment names", () => {
    expect(() => getRuntimeConfig(configEnv({ ENVIRONMENT: "prodution" }))).toThrow(/ENVIRONMENT/)
  })
})
