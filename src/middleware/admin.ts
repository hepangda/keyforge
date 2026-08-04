import { createMiddleware } from "hono/factory"
import { getUserGroupNames } from "../db/queries/users"
import { isYoloEnabled } from "../operations/yolo"
import { verifyCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import { nowSeconds } from "../utils/time"

const ADMIN_GROUP = "admins"
const ADMIN_RECENT_AUTH_SECONDS = 10 * 60

export const requireAdmin = createMiddleware<AppBindings>(async (c, next) => {
  const user = c.get("user")
  if (user === undefined) {
    return c.json({ error: "unauthorized" }, 401)
  }
  const groups = await getUserGroupNames(c.env, user.id)
  // YOLO mode grants administrator authority to any authenticated user. A
  // session is still required so `c.get("user")` stays defined downstream.
  if (!groups.includes(ADMIN_GROUP) && !isYoloEnabled(c.env)) {
    return c.json({ error: "forbidden" }, 403)
  }
  await next()
})

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"])

/**
 * Protect cookie-authenticated Admin API mutations from same-site, cross-origin
 * CSRF. SameSite cookies deliberately treat sibling subdomains as the same
 * site, so they are not a sufficient boundary for an identity provider.
 *
 * Browser callers on the issuer origin pass the Origin check. Non-browser
 * tooling can fetch GET /admin/csrf and echo the returned token in the
 * x-keyforge-csrf header (double-submit cookie verification).
 */
export const requireAdminMutationIntegrity = createMiddleware<AppBindings>(async (c, next) => {
  if (SAFE_METHODS.has(c.req.method.toUpperCase())) {
    await next()
    return
  }

  const expectedOrigin = new URL(c.env.ISSUER).origin
  const origin = c.req.header("origin")
  const fetchSite = c.req.header("sec-fetch-site")
  const sameOriginBrowser =
    origin === expectedOrigin && (fetchSite === undefined || fetchSite === "same-origin")
  const validDoubleSubmit = verifyCsrfToken(c, c.req.header("x-keyforge-csrf"))

  if (!sameOriginBrowser && !validDoubleSubmit) {
    return c.json({ error: "csrf_validation_failed" }, 403)
  }

  const session = c.get("session")
  if (
    !isYoloEnabled(c.env) &&
    (session === undefined || nowSeconds() - session.authTime > ADMIN_RECENT_AUTH_SECONDS)
  ) {
    return c.json({ error: "reauthentication_required" }, 403)
  }
  await next()
})
