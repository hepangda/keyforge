import { describe, expect, it } from "vitest"
import {
  ACCOUNT_BROWSER_SCRIPT,
  CONSOLE_BROWSER_SCRIPT,
  LOGIN_BROWSER_SCRIPT,
} from "../../src/views/browser-scripts"

describe("browser script isolation", () => {
  it("defines the recent-authentication redirect helper inside the account bundle", () => {
    expect(ACCOUNT_BROWSER_SCRIPT).toContain("const redirectForReauthentication=")
    expect(ACCOUNT_BROWSER_SCRIPT).toContain('body.error==="recent_authentication_required"')
  })

  it("does not ship the account-only redirect helper in the login bundle", () => {
    expect(LOGIN_BROWSER_SCRIPT).not.toContain("redirectForReauthentication")
  })

  it("progressively enhances the Console application wizard", () => {
    expect(CONSOLE_BROWSER_SCRIPT).toContain("[data-console-wizard]")
    expect(CONSOLE_BROWSER_SCRIPT).toContain('form.dataset.wizardReady="1"')
    expect(CONSOLE_BROWSER_SCRIPT).toContain("updateReview")
    expect(CONSOLE_BROWSER_SCRIPT).toContain("setKindDefaults")
    expect(CONSOLE_BROWSER_SCRIPT).toContain("client_credentials")
    expect(CONSOLE_BROWSER_SCRIPT).toContain("suggestResource")
    expect(CONSOLE_BROWSER_SCRIPT).toContain("syncDefaultResource")
    expect(() => new Function(CONSOLE_BROWSER_SCRIPT)).not.toThrow()
  })
})
