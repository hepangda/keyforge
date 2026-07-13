import { describe, expect, it } from "vitest"
import { pager } from "../../src/views/console/components"

describe("console pager", () => {
  it("does not offer an empty next page when a full page is final", () => {
    const html = pager("/console/users", 50, 0, 50, false)

    expect(html).toContain("Showing 1–50")
    expect(html).not.toContain(">Next</a>")
  })

  it("offers Next only when the lookahead query found another row", () => {
    const html = pager("/console/audit?event_type=login", 25, 0, 25, true)

    expect(html).toContain("/console/audit?event_type=login&amp;")
    expect(html).toContain("limit=25&amp;offset=25")
    expect(html).toContain(">Next</a>")
  })

  it("renders a recoverable empty tail without an invalid range", () => {
    const html = pager("/console/devices", 50, 50, 0, false)

    expect(html).toContain("No results on this page.")
    expect(html).toContain("limit=50&amp;offset=0")
    expect(html).toContain(">Previous</a>")
    expect(html).not.toContain("Showing 51–50")
  })
})
