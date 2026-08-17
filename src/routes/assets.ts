import { Hono } from "hono"
import { APPLE_TOUCH_ICON, FAVICON_ICO, FAVICON_SVG } from "../assets/web-icons"
import type { AppBindings } from "../types/app"
import {
  ACCOUNT_BROWSER_SCRIPT,
  AVATAR_BROWSER_SCRIPT,
  CONSOLE_BROWSER_SCRIPT,
  FORMS_BROWSER_SCRIPT,
  LOGIN_BROWSER_SCRIPT,
} from "../views/browser-scripts"

export const assets = new Hono<AppBindings>()

type AssetBody = string | Uint8Array

const assetEtags = new Map<AssetBody, Promise<string>>()

function assetEtag(body: AssetBody): Promise<string> {
  const cached = assetEtags.get(body)
  if (cached !== undefined) return cached
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body
  const digest = crypto.subtle
    .digest("SHA-256", bytes)
    .then(
      (value) =>
        `"${Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join("")}"`,
    )
  assetEtags.set(body, digest)
  return digest
}

async function asset(
  body: AssetBody,
  contentType: string,
  cacheControl: string,
  ifNoneMatch: string | undefined,
): Promise<Response> {
  const etag = await assetEtag(body)
  const headers = {
    "content-type": contentType,
    "cache-control": cacheControl,
    etag,
  }
  const matches =
    ifNoneMatch?.split(",").some((candidate) => {
      const normalized = candidate.trim()
      return normalized === "*" || normalized.replace(/^W\//, "") === etag
    }) ?? false
  if (matches) {
    return new Response(null, { status: 304, headers })
  }
  return new Response(typeof body === "string" ? body : body.slice(), { headers })
}

function script(body: string, ifNoneMatch: string | undefined): Promise<Response> {
  return asset(body, "application/javascript; charset=utf-8", "public, no-cache", ifNoneMatch)
}

assets.get("/assets/login.js", (c) => script(LOGIN_BROWSER_SCRIPT, c.req.header("if-none-match")))
assets.get("/assets/account.js", (c) =>
  script(ACCOUNT_BROWSER_SCRIPT, c.req.header("if-none-match")),
)
assets.get("/assets/avatar.js", (c) => script(AVATAR_BROWSER_SCRIPT, c.req.header("if-none-match")))
assets.get("/assets/forms.js", (c) => script(FORMS_BROWSER_SCRIPT, c.req.header("if-none-match")))
assets.get("/assets/console.js", (c) =>
  script(CONSOLE_BROWSER_SCRIPT, c.req.header("if-none-match")),
)

const ICON_CACHE_CONTROL = "public, max-age=86400, stale-while-revalidate=604800"

assets.get("/favicon.svg", (c) =>
  asset(
    FAVICON_SVG,
    "image/svg+xml; charset=utf-8",
    ICON_CACHE_CONTROL,
    c.req.header("if-none-match"),
  ),
)
assets.get("/favicon.ico", (c) =>
  asset(FAVICON_ICO, "image/x-icon", ICON_CACHE_CONTROL, c.req.header("if-none-match")),
)
assets.get("/apple-touch-icon.png", (c) =>
  asset(APPLE_TOUCH_ICON, "image/png", ICON_CACHE_CONTROL, c.req.header("if-none-match")),
)
