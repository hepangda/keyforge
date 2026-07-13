import type { Context } from "hono"
import { createMiddleware } from "hono/factory"
import { getUserGroupNames } from "../db/queries/users"
import type { AppBindings } from "../types/app"
import { nowSeconds } from "../utils/time"
import { renderForbidden } from "../views/console/layout"

const ADMIN_GROUP = "admins"
const RECENT_AUTH_SECONDS = 10 * 60
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"])
const MANAGEMENT_FORM_PATHS = [
  /^\/console\/(?:users|clients|resources)\/(?:new|[^/]+)\/?$/,
  /^\/console\/clients\/[^/]+\/(?:delete|rotate-secret)\/?$/,
  /^\/console\/groups\/[^/]+\/delete\/?$/,
]

function fallbackConsoleReturnPath(pathname: string): string {
  const parts = pathname.split("/").filter((part) => part !== "")
  const section = parts[1]
  if (section === "groups") {
    const id = parts[2]
    if (id !== undefined && parts[3] === "delete") return `/console/groups/${id}/delete`
    return "/console/users"
  }
  if (section === "devices") return "/console/devices"
  if (section === "users" || section === "clients" || section === "resources") {
    if (parts.length === 2) return `/console/${section}/new`
    const id = parts[2]
    if (
      section === "clients" &&
      id !== undefined &&
      (parts[3] === "delete" || parts[3] === "rotate-secret")
    ) {
      return `/console/clients/${id}/${parts[3]}`
    }
    if (id !== undefined) return `/console/${section}/${id}`
  }
  return "/console"
}

function consoleReturnPath(c: Context<AppBindings>): string {
  const fallback = fallbackConsoleReturnPath(new URL(c.req.url).pathname)
  const referer = c.req.header("referer")
  if (referer === undefined) return fallback
  try {
    const url = new URL(referer)
    if (
      url.origin === new URL(c.env.ISSUER).origin &&
      (url.pathname === "/console" || url.pathname.startsWith("/console/"))
    ) {
      return `${url.pathname}${url.search}`
    }
  } catch {
    return fallback
  }
  return fallback
}

export const requireConsoleAdmin = createMiddleware<AppBindings>(async (c, next) => {
  const user = c.get("user")
  if (user === undefined) {
    const url = new URL(c.req.url)
    return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`)
  }
  const groups = await getUserGroupNames(c.env, user.id)
  if (!groups.includes(ADMIN_GROUP)) {
    return c.html(renderForbidden(), 403)
  }
  const method = c.req.method.toUpperCase()
  const url = new URL(c.req.url)
  const isManagementFormEntry =
    method === "GET" && MANAGEMENT_FORM_PATHS.some((pattern) => pattern.test(url.pathname))
  if (!SAFE_METHODS.has(method) || isManagementFormEntry) {
    const session = c.get("session")
    if (session === undefined || nowSeconds() - session.authTime > RECENT_AUTH_SECONDS) {
      const params = new URLSearchParams({
        reauth: "1",
        return_to: isManagementFormEntry ? `${url.pathname}${url.search}` : consoleReturnPath(c),
      })
      return c.redirect(`/login?${params.toString()}`)
    }
  }
  await next()
})
