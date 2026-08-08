import type { Context } from "hono"
import { createMiddleware } from "hono/factory"
import { getUserGroupNames } from "../db/queries/users"
import { isYoloEnabled } from "../operations/yolo"
import type { AppBindings } from "../types/app"
import { nowSeconds } from "../utils/time"
import { renderForbidden } from "../views/console/layout"

const ADMIN_GROUP = "admins"
const RECENT_AUTH_SECONDS = 10 * 60
const SAFE_METHODS: Readonly<Record<string, true>> = { GET: true, HEAD: true, OPTIONS: true }
const MANAGEMENT_FORM_PATHS = [
  /^\/console\/groups\/(?:new|[^/]+)(?:\/(?:settings|access|delete))?\/?$/,
  /^\/console\/users\/(?:new|[^/]+)(?:\/(?:disable|revoke-sessions|(?:passwords|passkeys)\/[^/]+\/delete))?\/?$/,
  /^\/console\/clients\/(?:new|[^/]+)(?:\/(?:disable|rotate-secret|delete))?\/?$/,
  /^\/console\/resources\/(?:new|[^/]+)(?:\/delete)?\/?$/,
  /^\/console\/devices\/[^/]+\/revoke\/?$/,
]

function fallbackConsoleReturnPath(pathname: string): string {
  const parts = pathname.split("/").filter((part) => part !== "")
  const section = parts[1]
  if (section === "groups") {
    const id = parts[2]
    if (id === undefined) return "/console/groups/new"
    if (parts[3] === "delete") return `/console/groups/${id}/delete`
    if (parts[3] === "settings" || parts[3] === "access") {
      return `/console/groups/${id}?view=${parts[3]}`
    }
    return `/console/groups/${id}`
  }
  if (section === "devices") {
    const id = parts[2]
    return id === undefined ? "/console/devices" : `/console/devices/${id}/revoke`
  }
  if (section === "users" || section === "clients" || section === "resources") {
    if (parts.length === 2) return `/console/${section}/new`
    const id = parts[2]
    if (id === undefined) return `/console/${section}`
    const suffix = parts.slice(3).join("/")
    return suffix === "" ? `/console/${section}/${id}` : `/console/${section}/${id}/${suffix}`
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
function withDraftRestore(path: string): string {
  const url = new URL(path, "https://keyforge.invalid")
  url.searchParams.set("draft", "1")
  return `${url.pathname}${url.search}${url.hash}`
}

export const requireConsoleAdmin = createMiddleware<AppBindings>(async (c, next) => {
  const user = c.get("user")
  if (user === undefined) {
    const url = new URL(c.req.url)
    return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`)
  }
  const groups = await getUserGroupNames(c.env, user.id)
  const yolo = isYoloEnabled(c.env)
  // YOLO mode grants console administrator authority to any signed-in user.
  if (!groups.includes(ADMIN_GROUP) && !yolo) {
    return c.html(renderForbidden(c.get("i18n"), user.email), 403)
  }
  const method = c.req.method.toUpperCase()
  const url = new URL(c.req.url)
  const isManagementFormEntry =
    method === "GET" && MANAGEMENT_FORM_PATHS.some((pattern) => pattern.test(url.pathname))
  if ((SAFE_METHODS[method] !== true || isManagementFormEntry) && !yolo) {
    const session = c.get("session")
    if (session === undefined || nowSeconds() - session.authTime > RECENT_AUTH_SECONDS) {
      const params = new URLSearchParams({
        reauth: "1",
        hint: "admin_action",
        return_to: isManagementFormEntry
          ? `${url.pathname}${url.search}`
          : withDraftRestore(consoleReturnPath(c)),
      })
      return c.redirect(`/login?${params.toString()}`)
    }
  }
  await next()
})
