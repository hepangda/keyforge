import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

const ISSUER = "https://auth.pangda.app"
const LANGUAGE_COOKIE = "__Host-keyforge_language"

function languageSetCookie(response: Response): string | undefined {
  return response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${LANGUAGE_COOKIE}=`))
}

function cookieValue(response: Response, name: string): string {
  const cookie = response.headers.getSetCookie().find((value) => value.startsWith(`${name}=`))
  return cookie?.slice(name.length + 1).split(";")[0] ?? ""
}

async function loginAdmin(language: "en" | "zh-CN" | "ja"): Promise<string> {
  const languageCookie = `${LANGUAGE_COOKIE}=${language}`
  const page = await SELF.fetch(`${ISSUER}/login`, { headers: { cookie: languageCookie } })
  const csrf = cookieValue(page, "__Host-keyforge_csrf")
  const response = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `${languageCookie}; __Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({
      email: "admin",
      password: "test-admin-password-2026",
      csrf_token: csrf,
      return_to: "/",
    }).toString(),
    redirect: "manual",
  })
  return cookieValue(response, "__Host-keyforge_session")
}

describe("request language selection", () => {
  it("defaults to English when no preference or supported environment language exists", async () => {
    const response = await SELF.fetch(`${ISSUER}/login`, {
      headers: { "accept-language": "fr-FR, de;q=0.8" },
    })
    const html = await response.text()

    expect(response.status).toBe(200)
    expect(response.headers.get("content-language")).toBe("en")
    expect(html).toContain('<html lang="en">')
    expect(html).toContain("Sign in to KeyForge")
  })

  it("uses the browser environment before a preference has been saved", async () => {
    const japanese = await SELF.fetch(`${ISSUER}/login`, {
      headers: { "accept-language": "ja-JP, en;q=0.8" },
    })
    const japaneseHtml = await japanese.text()
    expect(japanese.headers.get("content-language")).toBe("ja")
    expect(japaneseHtml).toContain('<html lang="ja">')
    expect(japaneseHtml).toContain("KeyForge にログイン")
    expect(japaneseHtml).toContain('class="language-picker language-picker--card"')
    expect(japaneseHtml).toContain('<option value="auto" selected>')

    const chinese = await SELF.fetch(`${ISSUER}/login`, {
      headers: { "accept-language": "zh-Hans-CN" },
    })
    const chineseHtml = await chinese.text()
    expect(chinese.headers.get("content-language")).toBe("zh-CN")
    expect(chineseHtml).toContain('<html lang="zh-CN">')
    expect(chineseHtml).toContain("登录 KeyForge")
  })

  it("gives the saved choice priority over Accept-Language", async () => {
    const response = await SELF.fetch(`${ISSUER}/login`, {
      headers: {
        "accept-language": "ja-JP",
        cookie: `${LANGUAGE_COOKIE}=en`,
      },
    })
    const html = await response.text()

    expect(response.headers.get("content-language")).toBe("en")
    expect(html).toContain("Sign in to KeyForge")
    expect(html).toContain('<option value="en" selected>')
  })

  it("carries the selected language through account and admin surfaces", async () => {
    const session = await loginAdmin("ja")
    expect(session).not.toBe("")
    const cookie = `${LANGUAGE_COOKIE}=ja; __Host-keyforge_session=${session}`

    const dashboard = await SELF.fetch(`${ISSUER}/`, { headers: { cookie } })
    const dashboardHtml = await dashboard.text()
    expect(dashboardHtml).toContain('<html lang="ja">')
    expect(dashboardHtml).toContain('class="language-picker language-picker--shell"')
    expect(dashboardHtml).not.toContain('class="language-picker language-picker--card"')
    expect(dashboardHtml).toContain("プロフィール")
    expect(dashboardHtml).toContain("承認済みアプリ")
    expect(dashboardHtml).toContain("アカウント情報と、承認済みアプリに共有される情報です。")

    const consoleResponse = await SELF.fetch(`${ISSUER}/console`, { headers: { cookie } })
    const consoleHtml = await consoleResponse.text()
    expect(consoleHtml).toContain("管理コンソール")
    expect(consoleHtml).toContain("概要")
    expect(consoleHtml).toContain("最近のアクティビティ")
  })

  it("persists a language choice and returns to the same local page", async () => {
    const response = await SELF.fetch(
      `${ISSUER}/language?language=ja&return_to=${encodeURIComponent("/login?reauth=1")}`,
      { redirect: "manual" },
    )
    const cookie = languageSetCookie(response)

    expect(response.status).toBe(303)
    expect(response.headers.get("location")).toBe("/login?reauth=1")
    expect(cookie).toContain(`${LANGUAGE_COOKIE}=ja`)
    expect(cookie).toContain("Max-Age=31536000")
    expect(cookie).toContain("Path=/")
    expect(cookie).toContain("HttpOnly")
    expect(cookie).toContain("Secure")
    expect(cookie).toContain("SameSite=Lax")
  })

  it("can return to browser-controlled language and rejects external return targets", async () => {
    const response = await SELF.fetch(
      `${ISSUER}/language?language=auto&return_to=${encodeURIComponent("//evil.example/path")}`,
      {
        headers: { cookie: `${LANGUAGE_COOKIE}=zh-CN` },
        redirect: "manual",
      },
    )
    const cookie = languageSetCookie(response)

    expect(response.status).toBe(303)
    expect(response.headers.get("location")).toBe("/")
    expect(cookie).toContain(`${LANGUAGE_COOKIE}=`)
    expect(cookie).toContain("Max-Age=0")
  })
})
