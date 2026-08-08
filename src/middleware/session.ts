import { createMiddleware } from "hono/factory"
import { getAuthenticatedSessionByToken, touchSession } from "../auth/session"
import { getSessionCookie } from "../security/cookies"
import type { AppBindings } from "../types/app"

const SESSIONLESS_OAUTH_PATHS = new Set([
  "/oauth/token",
  "/oauth/userinfo",
  "/oauth/device_authorization",
  "/oauth/revoke",
  "/oauth/introspect",
])

function isSessionlessPath(path: string): boolean {
  return (
    path === "/health" ||
    path.startsWith("/health/") ||
    path === "/language" ||
    path === "/setup/bootstrap" ||
    path.startsWith("/assets/") ||
    path.startsWith("/avatars/") ||
    path.startsWith("/.well-known/") ||
    SESSIONLESS_OAUTH_PATHS.has(path)
  )
}

export const sessionMiddleware = createMiddleware<AppBindings>(async (c, next) => {
  if (isSessionlessPath(new URL(c.req.url).pathname)) {
    await next()
    return
  }
  const token = getSessionCookie(c)
  if (token !== undefined) {
    const authenticated = await getAuthenticatedSessionByToken(c.env, token)
    if (authenticated !== null) {
      c.set("session", authenticated.session)
      c.set("user", authenticated.user)
      const now = Math.floor(Date.now() / 1000)
      if (now - authenticated.session.lastSeenAt >= 5 * 60) {
        c.executionCtx.waitUntil(touchSession(c.env, authenticated.session.id, now))
      }
    }
  }
  await next()
})

export const requireAuth = createMiddleware<AppBindings>(async (c, next) => {
  if (c.get("user") === undefined) {
    const url = new URL(c.req.url)
    return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`)
  }
  await next()
})
