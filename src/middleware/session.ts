import { createMiddleware } from "hono/factory"
import { getSessionByToken, touchSession } from "../auth/session"
import { getUserById } from "../db/queries/users"
import { getSessionCookie } from "../security/cookies"
import type { AppBindings } from "../types/app"

export const sessionMiddleware = createMiddleware<AppBindings>(async (c, next) => {
  const token = getSessionCookie(c)
  if (token !== undefined) {
    const session = await getSessionByToken(c.env, token)
    if (session !== null) {
      const user = await getUserById(c.env, session.userId)
      if (user !== null && !user.disabled) {
        c.set("session", session)
        c.set("user", user)
        const now = Math.floor(Date.now() / 1000)
        if (now - session.lastSeenAt >= 5 * 60) {
          c.executionCtx.waitUntil(touchSession(c.env, session.id, now))
        }
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
