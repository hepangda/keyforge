import type { Context } from "hono"
import { verifyCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import type { ConsoleChrome, ConsoleFlash, ConsoleSection } from "../views/console/layout"

const FLASH: Readonly<Record<string, ConsoleFlash>> = {
  user_updated: { kind: "ok", message: "User updated." },
  user_created: { kind: "ok", message: "User created with an initial password." },
  user_invited: { kind: "ok", message: "User created and invitation sent." },
  groups_updated: { kind: "ok", message: "Group access updated." },
  group_created: { kind: "ok", message: "Group created." },
  group_updated: { kind: "ok", message: "Group updated." },
  group_deleted: { kind: "ok", message: "Group deleted." },
  sessions_revoked: { kind: "ok", message: "All of that user's sessions were revoked." },
  client_created: { kind: "ok", message: "Client created." },
  client_updated: { kind: "ok", message: "Client updated." },
  client_deleted: { kind: "ok", message: "Client deleted." },
  client_enabled: { kind: "ok", message: "Client enabled." },
  client_disabled: { kind: "ok", message: "Client disabled." },
  resource_created: { kind: "ok", message: "Resource created." },
  resource_updated: { kind: "ok", message: "Resource updated." },
  device_revoked: { kind: "ok", message: "Device session revoked." },
  duplicate_user: { kind: "warn", message: "An account already uses that email address." },
  duplicate_group: { kind: "warn", message: "A group with that name already exists." },
  protected_group: { kind: "warn", message: "The admins group is protected." },
  invalid_groups: { kind: "warn", message: "Choose only groups that currently exist." },
  last_admin: {
    kind: "warn",
    message: "Keep at least one active user in the admins group.",
  },
  user_create_failed: {
    kind: "warn",
    message: "The account was not created. Check email delivery and try again.",
  },
  not_found: { kind: "warn", message: "That item no longer exists." },
  invalid: { kind: "warn", message: "Please check the form and try again." },
}

export function readFlash(c: Context<AppBindings>): ConsoleFlash | undefined {
  const key = c.req.query("flash")
  return key === undefined ? undefined : FLASH[key]
}

export function chrome(c: Context<AppBindings>, section: ConsoleSection): ConsoleChrome {
  const user = c.get("user")
  const base: ConsoleChrome = { section, adminEmail: user?.email ?? "" }
  const flash = readFlash(c)
  return flash === undefined ? base : { ...base, flash }
}

export async function readVerifiedForm(c: Context<AppBindings>): Promise<FormData | null> {
  const form = await c.req.raw.formData()
  return verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined) ? form : null
}

export function parseLines(raw: string): string[] {
  return raw
    .split(/[\r\n]+/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}
