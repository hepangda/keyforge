import type { Context } from "hono"
import { verifyCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import type { ConsoleChrome, ConsoleFlash, ConsoleSection } from "../views/console/layout"

const FLASH: Readonly<Record<string, ConsoleFlash>> = {
  user_updated: { kind: "ok", message: "User updated." },
  user_created: { kind: "ok", message: "User created with an initial password." },
  user_invited: { kind: "ok", message: "User created and invitation sent." },
  password_added: { kind: "ok", message: "Password login method added." },
  password_deleted: { kind: "ok", message: "Password login method deleted." },
  passkey_deleted: { kind: "ok", message: "Passkey login method deleted." },
  groups_updated: { kind: "ok", message: "Group access updated." },
  group_created: { kind: "ok", message: "Group created." },
  group_updated: { kind: "ok", message: "Group updated." },
  group_deleted: { kind: "ok", message: "Group deleted." },
  group_access_updated: { kind: "ok", message: "Permission-group access updated." },
  sessions_revoked: { kind: "ok", message: "All of that user's sessions were revoked." },
  client_created: { kind: "ok", message: "Client created." },
  client_updated: { kind: "ok", message: "Client updated." },
  client_deleted: { kind: "ok", message: "Client deleted." },
  client_enabled: { kind: "ok", message: "Client enabled." },
  client_disabled: { kind: "ok", message: "Client disabled." },
  resource_created: { kind: "ok", message: "Resource created." },
  resource_updated: { kind: "ok", message: "Resource updated." },
  resource_deleted: { kind: "ok", message: "Resource deleted." },
  device_revoked: { kind: "ok", message: "Device session revoked." },
  duplicate_user: { kind: "warn", message: "An account already uses that email address." },
  duplicate_alias: { kind: "warn", message: "An account already uses that username." },
  invalid_alias: {
    kind: "warn",
    message: "Usernames may contain only English letters, numbers, hyphens, and underscores.",
  },
  invalid_password: { kind: "warn", message: "That password does not meet this user's policy." },
  last_login_method: {
    kind: "warn",
    message: "Add another password or passkey before deleting the last login method.",
  },
  user_disabled: { kind: "warn", message: "Enable the user before generating a magic link." },
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

function consoleDraftKey(c: Context<AppBindings>): string | undefined {
  const url = new URL(c.req.url)
  const parts = url.pathname.split("/").filter(Boolean)
  const section = parts[1]
  const id = parts[2]
  if (section === "users" && id === "new") return "keyforge:form:user:new"
  if (section === "groups" && id !== undefined && parts[3] !== "delete") {
    if (id === "new") return "keyforge:form:group:new"
    const view = parts[3] === "access" || c.req.query("view") === "access" ? "access" : "settings"
    return `keyforge:form:group:${id}:${view}`
  }
  if (section === "clients" && id !== undefined) {
    if (id === "new") return "keyforge:form:client:new"
    const view = c.req.query("view") === "access" ? "access" : "settings"
    if (view === "settings" || view === "access") return `keyforge:form:client:${id}:${view}`
  }
  if (section === "resources" && id !== undefined) {
    return `keyforge:form:resource:${id}`
  }
  return undefined
}

export function chrome(c: Context<AppBindings>, section: ConsoleSection): ConsoleChrome {
  const user = c.get("user")
  const clearDraft = c.req.query("clear_draft")
  const clearDraftKey =
    clearDraft?.startsWith("keyforge:form:") === true && clearDraft.length <= 200
      ? clearDraft
      : undefined
  const draftKey = consoleDraftKey(c)
  const base: ConsoleChrome = {
    i18n: c.get("i18n"),
    section,
    adminEmail: user?.email ?? "",
    ...(clearDraftKey === undefined ? {} : { clearDraftKey }),
    ...(draftKey === undefined ? {} : { draftKey }),
  }
  const flash = readFlash(c)
  return flash === undefined ? base : { ...base, flash }
}

export function withClearedDraft(path: string, key: string): string {
  const url = new URL(path, "https://keyforge.invalid")
  url.searchParams.set("clear_draft", key)
  return `${url.pathname}${url.search}${url.hash}`
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
