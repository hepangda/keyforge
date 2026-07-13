import { describe, expect, it } from "vitest"
import { generateId, ID_PREFIX } from "../../src/utils/id"

describe("generateId", () => {
  it("prefixes the id with the requested type tag", () => {
    // Given the user prefix
    // When generating an id
    const id = generateId(ID_PREFIX.user)
    // Then it starts with `usr_` and carries a 26-char ULID body
    expect(id.startsWith("usr_")).toBe(true)
    expect(id.slice(4)).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/)
  })

  it("generates unique ids", () => {
    // Given many generated ids
    const ids = new Set(Array.from({ length: 1000 }, () => generateId(ID_PREFIX.session)))
    // Then all are distinct
    expect(ids.size).toBe(1000)
  })

  it("produces lexicographically sortable (time-ordered) ids", async () => {
    // Given two ids generated a tick apart
    const first = generateId(ID_PREFIX.audit)
    await new Promise((resolve) => setTimeout(resolve, 2))
    const second = generateId(ID_PREFIX.audit)
    // Then the later id sorts after the earlier one
    expect(second > first).toBe(true)
  })
})
