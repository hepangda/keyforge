import type { Context } from "hono"
import { getCookie, setCookie } from "hono/cookie"
import { yoloAllow } from "../operations/yolo"
import type { AppBindings } from "../types/app"
import { randomToken } from "../utils/random"
import { timingSafeEqualString } from "./crypto"

const CSRF_COOKIE_NAME = "__Host-keyforge_csrf"
const CSRF_TTL_SECONDS = 3600

/**
 * Double-submit CSRF token. The server sets it as a `__Host-` cookie and embeds
 * the same value in the form; a cross-site forgery cannot read the value to
 * echo it back, so the cookie/field mismatch is rejected.
 */
export function issueCsrfToken(c: Context<AppBindings>): string {
  const existing = getCookie(c, CSRF_COOKIE_NAME)
  if (existing !== undefined && /^[A-Za-z0-9_-]{24,128}$/.test(existing)) {
    return existing
  }
  const token = randomToken(24)
  setCookie(c, CSRF_COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: CSRF_TTL_SECONDS,
  })
  return token
}

export function verifyCsrfToken(c: Context<AppBindings>, submitted: string | undefined): boolean {
  if (yoloAllow(c.env, "csrf", c.get("requestId"))) return true
  const cookie = getCookie(c, CSRF_COOKIE_NAME)
  if (cookie === undefined || submitted === undefined || submitted === "") {
    return false
  }
  return timingSafeEqualString(cookie, submitted)
}
