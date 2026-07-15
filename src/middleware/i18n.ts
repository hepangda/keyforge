import { getCookie } from "hono/cookie"
import { createMiddleware } from "hono/factory"
import { createI18n, resolveLocale } from "../i18n"
import type { AppBindings } from "../types/app"

export const LANGUAGE_COOKIE_NAME = "__Host-keyforge_language"

export const i18nMiddleware = createMiddleware<AppBindings>(async (c, next) => {
  const url = new URL(c.req.url)
  const resolved = resolveLocale(
    getCookie(c, LANGUAGE_COOKIE_NAME),
    c.req.header("accept-language"),
  )
  // Do not reflect request queries into HTML. OAuth parameters and account
  // capability tokens can be sensitive; the same-origin browser script fills
  // the exact current URL only when the user submits the language picker.
  c.set("i18n", createI18n(resolved, url.pathname))
  await next()
  if (c.res.headers.get("content-type")?.toLowerCase().startsWith("text/html")) {
    c.header("content-language", resolved.locale)
  }
})
