import { Hono } from "hono"
import type { AppBindings } from "../types/app"
import {
  ACCOUNT_BROWSER_SCRIPT,
  CONSOLE_BROWSER_SCRIPT,
  FORMS_BROWSER_SCRIPT,
  LOGIN_BROWSER_SCRIPT,
} from "../views/browser-scripts"

export const assets = new Hono<AppBindings>()

function script(body: string): Response {
  return new Response(body, {
    headers: {
      "content-type": "application/javascript; charset=utf-8",
      "cache-control": "no-cache",
    },
  })
}

assets.get("/assets/login.js", () => script(LOGIN_BROWSER_SCRIPT))
assets.get("/assets/account.js", () => script(ACCOUNT_BROWSER_SCRIPT))
assets.get("/assets/forms.js", () => script(FORMS_BROWSER_SCRIPT))
assets.get("/assets/console.js", () => script(CONSOLE_BROWSER_SCRIPT))
