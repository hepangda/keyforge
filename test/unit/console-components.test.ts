import { describe, expect, it } from "vitest"
import { DEFAULT_I18N } from "../../src/i18n"
import { pager, secondaryTabs, textAreaField, textField } from "../../src/views/console/components"

describe("console pager", () => {
  it("does not offer an empty next page when a full page is final", () => {
    const html = pager(DEFAULT_I18N, "/console/users", 50, 0, 50, false)

    expect(html).toContain("Showing 1–50")
    expect(html).not.toContain(">Next</a>")
  })

  it("offers Next only when the lookahead query found another row", () => {
    const html = pager(DEFAULT_I18N, "/console/audit?event_type=login", 25, 0, 25, true)

    expect(html).toContain("/console/audit?event_type=login&amp;")
    expect(html).toContain("limit=25&amp;offset=25")
    expect(html).toContain(">Next</a>")
  })

  it("renders a recoverable empty tail without an invalid range", () => {
    const html = pager(DEFAULT_I18N, "/console/devices", 50, 50, 0, false)

    expect(html).toContain("No results on this page.")
    expect(html).toContain("limit=50&amp;offset=0")
    expect(html).toContain(">Previous</a>")
    expect(html).not.toContain("Showing 51–50")
  })
})

describe("console secondary tabs", () => {
  it("renders an independent labelled active tab set", () => {
    const html = secondaryTabs(DEFAULT_I18N, "User sections", [
      { label: "Profile", href: "/console/users/usr_1?view=profile", active: true },
      { label: "Sessions", href: "/console/users/usr_1?view=sessions", active: false },
    ])
    expect(html).toContain('<nav class="subtabs" aria-label="User sections">')
    expect(html).toContain('class="subtab subtab--active"')
    expect(html).toContain('aria-current="page"')
    expect(html).not.toContain("shell-tabs")
  })
})

describe("console fields", () => {
  it("associates text and textarea errors with stable ids", () => {
    const input = textField(DEFAULT_I18N, "Display name", "name", "Draft", {
      error: "Check the form values.",
    })
    expect(input).toContain('id="name-field"')
    expect(input).toContain('aria-invalid="true"')
    expect(input).toContain('aria-describedby="name-error"')
    expect(input).toContain('id="name-error"')

    const textarea = textAreaField(
      DEFAULT_I18N,
      "Allowed scopes",
      "allowed_scopes",
      "openid",
      undefined,
      { error: "Check the form values." },
    )
    expect(textarea).toContain('aria-describedby="allowed_scopes-error"')
  })
})
