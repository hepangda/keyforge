import { describe, expect, it } from "vitest"
import { magicLinkEmail } from "../../src/email/templates"
import { createI18n, localeFromAcceptLanguage, resolveLocale, translate } from "../../src/i18n"

describe("i18n locale resolution", () => {
  it("uses supported Accept-Language entries by quality and order", () => {
    expect(localeFromAcceptLanguage("fr-FR, ja-JP;q=0.9, en-US;q=0.8")).toBe("ja")
    expect(localeFromAcceptLanguage("zh-Hant-TW, ja;q=0.5")).toBe("zh-CN")
    expect(localeFromAcceptLanguage("ja;q=0, en-GB;q=0.7")).toBe("en")
    expect(localeFromAcceptLanguage("fr-FR, *;q=0.8, ja;q=0.5")).toBe("en")
    expect(localeFromAcceptLanguage("ja;q=invalid, zh-CN;q=0.5")).toBe("zh-CN")
  })

  it("lets a valid saved preference override the browser environment", () => {
    expect(resolveLocale("en", "ja-JP")).toEqual({
      locale: "en",
      preference: "en",
      source: "preference",
    })
    expect(resolveLocale("not-a-locale", "ja-JP")).toEqual({
      locale: "ja",
      preference: "auto",
      source: "environment",
    })
  })

  it("falls back to English when the environment has no supported language", () => {
    expect(resolveLocale(undefined, "fr-FR, de;q=0.8")).toEqual({
      locale: "en",
      preference: "auto",
      source: "default",
    })
  })

  it("interpolates translated messages and formats dates for the locale", () => {
    expect(translate("zh-CN", "Continue as {email}.", { email: "alice@example.com" })).toBe(
      "以 alice@example.com 的身份继续。",
    )
    const japanese = createI18n({ locale: "ja", preference: "ja", source: "preference" })
    expect(japanese.formatDate(1_767_225_600)).toContain("2026")
  })

  it("uses 登录名 for alias-facing Chinese copy", () => {
    expect(translate("zh-CN", "Username")).toBe("登录名")
    expect(translate("zh-CN", "Email or username")).toBe("电子邮箱或登录名")
    expect(translate("zh-CN", "Only an administrator can change your username.")).toBe(
      "只有管理员可以更改您的登录名。",
    )
  })

  it("localizes transactional email content", () => {
    const email = magicLinkEmail("https://auth.example/login?token=secret", "ja")
    expect(email.subject).toBe("KeyForge ログインリンク")
    expect(email.text).toContain("KeyForge にログイン")
    expect(email.html).toContain("有効期限は15分")
  })
})
