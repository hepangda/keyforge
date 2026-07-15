import { Hono } from "hono"
import { deleteCookie, setCookie } from "hono/cookie"
import { isLocale } from "../i18n"
import { LANGUAGE_COOKIE_NAME } from "../middleware/i18n"
import { safeLocalPath } from "../security/return-to"
import type { AppBindings } from "../types/app"

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  path: "/",
} as const

export const language = new Hono<AppBindings>()

language.get("/language", (c) => {
  const preference = c.req.query("language")
  if (preference === "auto") {
    deleteCookie(c, LANGUAGE_COOKIE_NAME, COOKIE_OPTIONS)
  } else if (isLocale(preference)) {
    setCookie(c, LANGUAGE_COOKIE_NAME, preference, {
      ...COOKIE_OPTIONS,
      maxAge: 365 * 24 * 60 * 60,
    })
  }
  return c.redirect(safeLocalPath(c.req.query("return_to") ?? null), 303)
})
