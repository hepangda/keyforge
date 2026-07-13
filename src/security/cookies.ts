import type { Context } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import { SESSION_COOKIE_NAME } from "../config"
import type { AppBindings } from "../types/app"

const HOST_COOKIE_OPTIONS = { secure: true, sameSite: "Lax", path: "/" } as const

export function setSessionCookie(
  c: Context<AppBindings>,
  token: string,
  maxAgeSeconds: number,
): void {
  setCookie(c, SESSION_COOKIE_NAME, token, {
    ...HOST_COOKIE_OPTIONS,
    httpOnly: true,
    maxAge: maxAgeSeconds,
  })
}

export function clearSessionCookie(c: Context<AppBindings>): void {
  deleteCookie(c, SESSION_COOKIE_NAME, { ...HOST_COOKIE_OPTIONS, httpOnly: true })
}

export function getSessionCookie(c: Context<AppBindings>): string | undefined {
  return getCookie(c, SESSION_COOKIE_NAME)
}
