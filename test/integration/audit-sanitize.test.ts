import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { insertAuditBatch } from "../../src/security/audit"
import { AUDIT_DETAIL_MAX_BYTES, AUDIT_METADATA_MAX_BYTES } from "../../src/security/audit-sanitize"

const byteLength = (value: string): number => new TextEncoder().encode(value).byteLength

describe("audit queue persistence boundary", () => {
  it("normalizes oversized and cyclic fields before inserting D1", async () => {
    const id = "aud_test_sanitized_queue_message"
    await env.DB.prepare("DELETE FROM audit_logs WHERE id = ?").bind(id).run()
    const metadata: Record<string, unknown> = { payload: "x".repeat(20_000) }
    metadata["self"] = metadata
    Object.defineProperty(metadata, "__proto__", {
      configurable: true,
      enumerable: true,
      value: { polluted: true },
    })

    await insertAuditBatch(env, [
      {
        id,
        type: "security.invalid_client",
        detail: "😀".repeat(2_000),
        metadata,
        createdAt: 1_700_000_000,
      },
    ])

    const row = await env.DB.prepare("SELECT detail, metadata_json FROM audit_logs WHERE id = ?")
      .bind(id)
      .first<{ detail: string; metadata_json: string }>()
    expect(row).not.toBeNull()
    if (row === null) return
    expect(byteLength(row.detail)).toBeLessThanOrEqual(AUDIT_DETAIL_MAX_BYTES)
    expect(byteLength(row.metadata_json)).toBeLessThanOrEqual(AUDIT_METADATA_MAX_BYTES)
    const parsed = JSON.parse(row.metadata_json) as Record<string, unknown>
    expect(Object.hasOwn(parsed, "__proto__")).toBe(false)
    expect(parsed["_truncated"]).toBe(true)
  })
})
