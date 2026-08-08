import { Hono } from "hono"
import type { AppBindings } from "../types/app"
import {
  ACCOUNT_BROWSER_SCRIPT,
  AVATAR_BROWSER_SCRIPT,
  CONSOLE_BROWSER_SCRIPT,
  FORMS_BROWSER_SCRIPT,
  LOGIN_BROWSER_SCRIPT,
} from "../views/browser-scripts"

export const assets = new Hono<AppBindings>()

const scriptEtags = new Map<string, Promise<string>>()

function scriptEtag(body: string): Promise<string> {
  const cached = scriptEtags.get(body)
  if (cached !== undefined) return cached
  const digest = crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(body))
    .then(
      (value) =>
        `"${Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join("")}"`,
    )
  scriptEtags.set(body, digest)
  return digest
}

async function script(body: string, ifNoneMatch: string | undefined): Promise<Response> {
  const etag = await scriptEtag(body)
  const headers = {
    "content-type": "application/javascript; charset=utf-8",
    "cache-control": "public, no-cache",
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
  return new Response(body, {
    headers,
  })
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
