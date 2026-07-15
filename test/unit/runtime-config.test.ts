import { describe, expect, it } from "vitest"
import { getRuntimeConfig } from "../../src/operations/runtime-config"

function configEnv(overrides: Record<string, string> = {}): Env {
  return {
    ENVIRONMENT: "test",
    KEY_ROTATION_INTERVAL_SECONDS: "604800",
    TERMINAL_DATA_RETENTION_DAYS: "30",
    AUDIT_D1_RETENTION_DAYS: "90",
    MAINTENANCE_BATCH_SIZE: "100",
    MAINTENANCE_LEASE_SECONDS: "900",
    ...overrides,
  } as unknown as Env
}

describe("runtime maintenance configuration", () => {
  it("accepts bounded operator values", () => {
    const config = getRuntimeConfig(
      configEnv({
        KEY_ROTATION_INTERVAL_SECONDS: "86400",
        TERMINAL_DATA_RETENTION_DAYS: "7",
        AUDIT_D1_RETENTION_DAYS: "365",
        MAINTENANCE_BATCH_SIZE: "25",
        MAINTENANCE_LEASE_SECONDS: "120",
      }),
    )

    expect(config).toMatchObject({
      keyRotationIntervalSeconds: 86400,
      terminalDataRetentionDays: 7,
      auditD1RetentionDays: 365,
      maintenanceBatchSize: 25,
      maintenanceLeaseSeconds: 120,
    })
  })

  it("accepts only the prescribed remote audit windows", () => {
    expect(
      getRuntimeConfig(configEnv({ ENVIRONMENT: "staging", AUDIT_D1_RETENTION_DAYS: "90" }))
        .auditD1RetentionDays,
    ).toBe(90)
    expect(
      getRuntimeConfig(configEnv({ ENVIRONMENT: "production", AUDIT_D1_RETENTION_DAYS: "365" }))
        .auditD1RetentionDays,
    ).toBe(365)
  })

  it("falls back safely for malformed and out-of-range values", () => {
    const config = getRuntimeConfig(
      configEnv({
        KEY_ROTATION_INTERVAL_SECONDS: "0",
        TERMINAL_DATA_RETENTION_DAYS: "not-a-number",
        AUDIT_D1_RETENTION_DAYS: "366",
        MAINTENANCE_BATCH_SIZE: "101",
        MAINTENANCE_LEASE_SECONDS: "1",
      }),
    )

    expect(config).toMatchObject({
      keyRotationIntervalSeconds: 604800,
      terminalDataRetentionDays: 30,
      auditD1RetentionDays: 90,
      maintenanceBatchSize: 100,
      maintenanceLeaseSeconds: 900,
    })
  })

  it("fails closed for malformed remote values", () => {
    expect(() =>
      getRuntimeConfig(
        configEnv({
          ENVIRONMENT: "production",
          AUDIT_D1_RETENTION_DAYS: "365",
          MAINTENANCE_BATCH_SIZE: "101",
        }),
      ),
    ).toThrow(/MAINTENANCE_BATCH_SIZE/)

    expect(() =>
      getRuntimeConfig(
        configEnv({
          ENVIRONMENT: "production",
          AUDIT_D1_RETENTION_DAYS: "90",
        }),
      ),
    ).toThrow(/AUDIT_D1_RETENTION_DAYS/)

    expect(() =>
      getRuntimeConfig(
        configEnv({
          ENVIRONMENT: "staging",
          AUDIT_D1_RETENTION_DAYS: "91",
        }),
      ),
    ).toThrow(/AUDIT_D1_RETENTION_DAYS/)
  })

  it("rejects unknown environment names", () => {
    expect(() => getRuntimeConfig(configEnv({ ENVIRONMENT: "prodution" }))).toThrow(/ENVIRONMENT/)
  })
})
