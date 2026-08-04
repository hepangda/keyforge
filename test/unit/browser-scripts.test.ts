import { describe, expect, it } from "vitest"
import {
  ACCOUNT_BROWSER_SCRIPT,
  AVATAR_BROWSER_SCRIPT,
  CONSOLE_BROWSER_SCRIPT,
  FORMS_BROWSER_SCRIPT,
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

  it("fills the language return URL in the browser without reflecting request queries in HTML", () => {
    expect(FORMS_BROWSER_SCRIPT).toContain("[data-language-picker]")
    expect(FORMS_BROWSER_SCRIPT).toContain('select[name="language"]')
    expect(FORMS_BROWSER_SCRIPT).toContain("form.requestSubmit()")
    expect(FORMS_BROWSER_SCRIPT).toContain(
      "window.location.pathname+window.location.search+window.location.hash",
    )
    expect(() => new Function(FORMS_BROWSER_SCRIPT)).not.toThrow()
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

describe("avatar uploader script", () => {
  it("uploads in the page and asks for a machine-readable answer", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain("event.preventDefault()")
    expect(AVATAR_BROWSER_SCRIPT).toContain('accept:"application/json"')
    expect(AVATAR_BROWSER_SCRIPT).toContain('credentials:"same-origin"')
  })

  it("resizes and re-encodes before upload so large photos never reach the limit", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain("canvas")
    expect(AVATAR_BROWSER_SCRIPT).toContain('encode("image/webp"')
    expect(AVATAR_BROWSER_SCRIPT).toContain('encode("image/jpeg"')
  })

  it("crops with a selection rectangle over the whole image", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain("data-avatar-cropper")
    expect(AVATAR_BROWSER_SCRIPT).toContain("clampSelection")
    expect(AVATAR_BROWSER_SCRIPT).toContain("resizeFrom")
    expect(AVATAR_BROWSER_SCRIPT).toContain("hitHandle")
    expect(AVATAR_BROWSER_SCRIPT).toContain("resetSelection")
    // The old pan-behind-a-viewport model is gone.
    expect(AVATAR_BROWSER_SCRIPT).not.toContain("baseScale")
    expect(AVATAR_BROWSER_SCRIPT).not.toContain("data-avatar-zoom")
  })

  it("keeps the selection square and inside the image", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain(
      "var side=Math.max(Math.abs(px-anchorX),Math.abs(py-anchorY))",
    )
    expect(AVATAR_BROWSER_SCRIPT).toContain("Math.max(0,Math.min(crop.viewW-crop.size,crop.x))")
    // A panorama's viewport can be shorter than the nominal minimum side.
    expect(AVATAR_BROWSER_SCRIPT).toContain("var minSide=function()")
  })

  it("clamps the rendered region to the source image bounds", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain(
      "Math.max(0,Math.min(crop.image.naturalWidth-sourceSide,crop.x*crop.sourceScale))",
    )
    expect(AVATAR_BROWSER_SCRIPT).toContain(
      "var sourceScale=Math.max(image.naturalWidth/viewW,image.naturalHeight/viewH)",
    )
  })

  it("supports keyboard move and resize for pointer-free use", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain("keydown")
    expect(AVATAR_BROWSER_SCRIPT).toContain("ArrowLeft")
    expect(AVATAR_BROWSER_SCRIPT).toContain("ArrowDown")
  })

  it("uploads the cropped square rather than the originally chosen file", () => {
    expect(AVATAR_BROWSER_SCRIPT).toContain("renderCrop()")
    expect(AVATAR_BROWSER_SCRIPT).toContain("var prepared=rendered||file")
  })

  it("maps each server error to its own localized message", () => {
    for (const error of [
      "avatar_too_large",
      "avatar_unsupported",
      "avatar_missing",
      "avatar_rate_limited",
    ]) {
      expect(AVATAR_BROWSER_SCRIPT).toContain(error)
    }
  })

  it("stays out of the other bundles", () => {
    expect(ACCOUNT_BROWSER_SCRIPT).not.toContain("data-avatar-form")
    expect(LOGIN_BROWSER_SCRIPT).not.toContain("data-avatar-form")
  })
})
