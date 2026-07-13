import { describe, expect, it } from "vitest"
import {
  AUDIT_DETAIL_MAX_BYTES,
  AUDIT_METADATA_MAX_BYTES,
  AUDIT_METADATA_MAX_KEYS,
  isBoundedAuditMetadata,
  sanitizeAuditDetail,
  sanitizeAuditMetadata,
} from "../../src/security/audit-sanitize"

const byteLength = (value: string): number => new TextEncoder().encode(value).byteLength

describe("audit field sanitization", () => {
  it("truncates detail at a UTF-8 byte boundary", () => {
    const detail = sanitizeAuditDetail("😀".repeat(1_000))
    expect(byteLength(detail)).toBeLessThanOrEqual(AUDIT_DETAIL_MAX_BYTES)
    expect(detail.endsWith("�")).toBe(false)
  })

  it("makes cyclic and oversized metadata bounded and JSON-safe", () => {
    const metadata: Record<string, unknown> = {
      message: "m".repeat(20_000),
      array: Array.from({ length: 100 }, (_, index) => ({ index, text: "x".repeat(1_000) })),
    }
    metadata["self"] = metadata
    for (let index = 0; index < 50; index += 1) {
      metadata[`key_${index}`] = "value"
    }

    const sanitized = sanitizeAuditMetadata(metadata)
    expect(sanitized).not.toBeNull()
    expect(sanitized).not.toBeUndefined()
    if (sanitized === null || sanitized === undefined) return
    const serialized = JSON.stringify(sanitized)
    expect(byteLength(serialized)).toBeLessThanOrEqual(AUDIT_METADATA_MAX_BYTES)
    expect(Object.keys(sanitized).length).toBeLessThanOrEqual(AUDIT_METADATA_MAX_KEYS)
    expect(sanitized["_truncated"]).toBe(true)
    expect(isBoundedAuditMetadata(sanitized)).toBe(true)
  })

  it("rejects metadata that bypasses a structural bound", () => {
    expect(isBoundedAuditMetadata({ value: "x".repeat(513) })).toBe(false)
    expect(isBoundedAuditMetadata({ ["k".repeat(65)]: true })).toBe(false)
    expect(isBoundedAuditMetadata({ nested: { one: { two: { three: {} } } } })).toBe(false)
  })

  it("drops prototype-mutating keys", () => {
    const metadata = Object.create(null) as Record<string, unknown>
    metadata["safe"] = "value"
    Object.defineProperty(metadata, "__proto__", {
      configurable: true,
      enumerable: true,
      value: { polluted: true },
    })
    metadata["constructor"] = { prototype: { polluted: true } }

    const sanitized = sanitizeAuditMetadata(metadata)
    expect(sanitized).not.toBeNull()
    expect(sanitized).not.toBeUndefined()
    if (sanitized === null || sanitized === undefined) return
    expect(Object.hasOwn(sanitized, "__proto__")).toBe(false)
    expect(Object.hasOwn(sanitized, "constructor")).toBe(false)
    expect(sanitized["safe"]).toBe("value")
    expect(sanitized["_truncated"]).toBe(true)
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined()
  })
})
