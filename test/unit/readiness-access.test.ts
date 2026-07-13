import { describe, expect, it } from "vitest"
import { readinessAccessStatus } from "../../src/routes/health"

const TOKEN = "a".repeat(64)

describe("readiness probe access", () => {
  it("keeps local readiness open", () => {
    expect(readinessAccessStatus("local", undefined, undefined)).toBe("allowed")
  })

  it("fails closed when a remote environment has no configured credential", () => {
    expect(readinessAccessStatus("staging", undefined, undefined)).toBe("misconfigured")
    expect(readinessAccessStatus("unexpected", undefined, undefined)).toBe("misconfigured")
    expect(readinessAccessStatus("production", "too-short", `Bearer ${TOKEN}`)).toBe(
      "misconfigured",
    )
    expect(readinessAccessStatus("production", "+".repeat(64), `Bearer ${TOKEN}`)).toBe(
      "misconfigured",
    )
  })

  it("requires the exact remote bearer credential", () => {
    expect(readinessAccessStatus("production", TOKEN, undefined)).toBe("unauthorized")
    expect(readinessAccessStatus("production", TOKEN, `Bearer ${"b".repeat(64)}`)).toBe(
      "unauthorized",
    )
    expect(readinessAccessStatus("production", TOKEN, `Bearer ${TOKEN}`)).toBe("allowed")
  })
})
