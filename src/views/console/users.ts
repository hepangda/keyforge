import type { PasswordCredentialSummary } from "../../auth/password"
import type { SessionSummary } from "../../auth/session"
import type { GroupSummary } from "../../db/queries/users"
import type { CredentialSummary } from "../../db/queries/webauthn"
import type { I18n } from "../../i18n"
import type { User } from "../../types/domain"
import { escapeHtml } from "../layout"
import { searchPicker } from "../search-picker"
import {
  checkboxField,
  csrfField,
  dataTable,
  fmtDate,
  pager,
  secondaryTabs,
  statusBadge,
  textField,
} from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

function groupChoices(
  i18n: I18n,
  groups: readonly GroupSummary[],
  selectedIds: ReadonlySet<string>,
): string {
  if (groups.length === 0) {
    return `<p class="form-hint"><a href="/console/groups/new">${escapeHtml(i18n.t("Create a group first"))}</a></p>`
  }
  return searchPicker(
    i18n,
    {
      id: "user-group-access",
      name: "group_ids",
      label: "Groups",
      placeholder: "Search permission groups",
      emptySelection: "No permission groups selected.",
      maxSelections: 100,
    },
    groups.map((group, index) => ({
      value: group.id,
      title: group.name,
      detail: group.description ?? i18n.t("No description"),
      meta: i18n.t(group.memberCount === 1 ? "{count} member" : "{count} members", {
        count: group.memberCount,
      }),
      selected: selectedIds.has(group.id),
      recommended: index < 6,
    })),
  )
}

export function renderUsersList(
  chrome: ConsoleChrome,
  users: readonly User[],
  query: string,
  limit: number,
  offset: number,
  hasNext: boolean,
): string {
  const { i18n } = chrome
  const userRows = users.map((user) => [
    `<b>${escapeHtml(user.alias)}</b>`,
    escapeHtml(user.email),
    statusBadge(i18n, !user.disabled, "Active", "Disabled"),
    `<span class="mono">${escapeHtml(fmtDate(i18n, user.createdAt))}</span>`,
    `<div class="actions"><a class="btn btn--ghost btn--tiny" href="/console/users/${escapeHtml(user.id)}">${escapeHtml(i18n.t("Manage"))}</a></div>`,
  ])
  const baseHref = query === "" ? "/console/users" : `/console/users?q=${encodeURIComponent(query)}`
  const clear =
    query === ""
      ? ""
      : `<a class="btn btn--ghost btn--tiny" href="/console/users">${escapeHtml(i18n.t("Clear"))}</a>`
  const search = `<form method="get" action="/console/users" class="actions"><label class="field"><span class="field__label">${escapeHtml(i18n.t("Search users"))}</span><input class="input input--compact" name="q" value="${escapeHtml(query)}" maxlength="120"></label><button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Search"))}</button>${clear}</form>`
  const emptyMessage =
    query === "" ? "No users found. Add the first account to begin." : "No users match this search."
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Identity directory"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Create accounts, invite people, and manage their login methods."))}</p></div><div class="actions">${search}<a class="btn btn--primary btn--sm" href="/console/users/new">${escapeHtml(i18n.t("Add user"))}</a></div></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Users"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Everyone who can sign in to this server."))}</p></div></div>${dataTable(i18n, ["Username", "Email", "Status", "Created", ""], userRows, emptyMessage)}<div class="panel__body">${pager(i18n, baseHref, limit, offset, users.length, hasNext)}</div></section>`
  return consoleShell(i18n.t("Users"), chrome, content)
}

export type UserCreateValues = {
  readonly email: string
  readonly alias: string
  readonly name: string
  readonly emailVerified: boolean
  readonly groupIds: readonly string[]
  readonly setupMode: "invite" | "password"
}

export type UserCreateField =
  | "email"
  | "alias"
  | "name"
  | "setup_mode"
  | "password"
  | "password_confirm"
  | "group_ids"

export type UserCreateFeedback = {
  readonly values: UserCreateValues
  readonly field: UserCreateField | null
  readonly error: string
}

export function renderUserCreate(
  chrome: ConsoleChrome,
  groups: readonly GroupSummary[],
  csrfToken: string,
  feedback?: UserCreateFeedback,
): string {
  const { i18n } = chrome
  const values = feedback?.values ?? {
    email: "",
    alias: "",
    name: "",
    emailVerified: false,
    groupIds: [],
    setupMode: "invite" as const,
  }
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
  const fieldError = (field: UserCreateField) =>
    feedback?.field === field ? feedback.error : undefined
  const selectedGroups = new Set(values.groupIds)
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Add a user"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Choose how the user will complete account setup."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/users">${escapeHtml(i18n.t("Back to users"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Account details"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Invitation and initial-password setup have distinct security effects."))}</p></div></div><div class="panel__body">${errorHtml}<form method="post" action="/console/users" class="form-grid" data-user-setup-form>${csrfField(csrfToken)}${textField(i18n, "Email", "email", values.email, { type: "email", required: true, placeholder: "name@example.com", error: fieldError("email") })}${textField(i18n, "Username", "alias", values.alias, { required: true, placeholder: "janedoe", error: fieldError("alias") })}<p class="form-hint form-hint--standalone form-hint--wide">${escapeHtml(i18n.t("English letters, numbers, hyphens, and underscores only; usernames are unique and can be used at sign-in."))}</p>${textField(i18n, "Display name", "name", values.name, { placeholder: "Optional", error: fieldError("name") })}${checkboxField(i18n, "Mark email as verified", "email_verified", values.emailVerified)}<fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Account setup"))}</legend><div class="choice-cards choice-cards--two"><label class="choice-card"><input type="radio" name="setup_mode" value="invite"${values.setupMode === "invite" ? " checked" : ""}><b>${escapeHtml(i18n.t("Send invitation"))}</b><small>${escapeHtml(i18n.t("Email a single-use link so the user chooses their password."))}</small></label><label class="choice-card"><input type="radio" name="setup_mode" value="password"${values.setupMode === "password" ? " checked" : ""}><b>${escapeHtml(i18n.t("Set initial password"))}</b><small>${escapeHtml(i18n.t("Create the account with a password you provide once."))}</small></label></div></fieldset><div class="field--wide" data-user-password-region>${textField(i18n, "Initial password", "password", "", { type: "password", error: fieldError("password") })}${textField(i18n, "Confirm password", "password_confirm", "", { type: "password", error: fieldError("password_confirm") })}<p class="form-hint">${escapeHtml(i18n.t("Initial passwords require 6–128 characters, or at least 12 when the admins group is selected."))}</p></div><fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Groups"))}</legend>${groupChoices(i18n, groups, selectedGroups)}</fieldset><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Create user"))}</button></div></form></div></section>`
  return consoleShell(i18n.t("Add user"), chrome, content)
}

export type UserDetailView = "profile" | "login-methods" | "access" | "sessions"

export type UserDetailFeedback =
  | {
      readonly view: "profile"
      readonly values: {
        readonly alias: string
        readonly name: string
        readonly emailVerified: boolean
      }
      readonly field: "alias" | "name" | null
      readonly error: string
    }
  | {
      readonly view: "login-methods"
      readonly values: { readonly passwordName: string }
      readonly field: "password" | null
      readonly error: string
    }

export type UserDetailData = {
  readonly user: User
  readonly view: UserDetailView
  readonly csrfToken: string
  readonly feedback?: UserDetailFeedback
  readonly groups?: readonly GroupSummary[]
  readonly selectedGroupIds?: ReadonlySet<string>
  readonly passwords?: readonly PasswordCredentialSummary[]
  readonly passkeys?: readonly CredentialSummary[]
  readonly passwordMinimum?: number
  readonly sessions?: readonly SessionSummary[]
}

function userHref(userId: string, view: UserDetailView): string {
  return `/console/users/${encodeURIComponent(userId)}?view=${view}`
}

function detailAlert(i18n: I18n, feedback: UserDetailFeedback | undefined): string {
  return feedback === undefined
    ? ""
    : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
}

export function renderUserDetail(chrome: ConsoleChrome, data: UserDetailData): string {
  const { i18n } = chrome
  const { user, view, csrfToken } = data
  const tabs = secondaryTabs(i18n, "User sections", [
    { label: "Profile", href: userHref(user.id, "profile"), active: view === "profile" },
    {
      label: "Login methods",
      href: userHref(user.id, "login-methods"),
      active: view === "login-methods",
    },
    { label: "Access", href: userHref(user.id, "access"), active: view === "access" },
    { label: "Sessions", href: userHref(user.id, "sessions"), active: view === "sessions" },
  ])
  const summary = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(user.name ?? user.alias)}</h2><p class="panel__desc"><span class="mono">@${escapeHtml(user.alias)}</span> · ${escapeHtml(user.email)} · ${statusBadge(i18n, !user.disabled, "Active", "Disabled")}</p></div><div class="actions"><a class="btn btn--ghost btn--sm" href="/console/audit?user_id=${encodeURIComponent(user.id)}">${escapeHtml(i18n.t("View audit events"))}</a><a class="btn btn--ghost btn--sm back-link" href="/console/users">${escapeHtml(i18n.t("Back to users"))}</a></div></div>${tabs}`
  let panel: string
  if (view === "profile") {
    const feedback = data.feedback?.view === "profile" ? data.feedback : undefined
    const values = feedback?.values ?? {
      alias: user.alias,
      name: user.name ?? "",
      emailVerified: user.emailVerified,
    }
    const fieldError = (field: "alias" | "name") =>
      feedback?.field === field ? feedback.error : undefined
    const lifecycle = user.disabled
      ? `<form method="post" action="/console/users/${escapeHtml(user.id)}/enable">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Enable user"))}</button></form>`
      : `<a class="btn btn--danger btn--auto" href="/console/users/${escapeHtml(user.id)}/disable">${escapeHtml(i18n.t("Disable user"))}</a>`
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Profile"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Identity attributes and account status."))}</p></div></div><div class="panel__body">${detailAlert(i18n, feedback)}<div class="meta"><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("User ID"))}</span><span class="meta__val mono">${escapeHtml(user.id)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Email"))}</span><span class="meta__val">${escapeHtml(user.email)}</span></div></div><form method="post" action="/console/users/${escapeHtml(user.id)}" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Username", "alias", values.alias, { required: true, error: fieldError("alias") })}${textField(i18n, "Display name", "name", values.name, { placeholder: "No name set", error: fieldError("name") })}${checkboxField(i18n, "Email verified", "email_verified", values.emailVerified)}<div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button></div></form><div class="action-list"><div class="action-row action-row--danger"><div><h3>${escapeHtml(i18n.t(user.disabled ? "Enable user" : "Disable user"))}</h3><p>${escapeHtml(i18n.t(user.disabled ? "Allow this user to sign in again." : "Review the sessions and refresh access that will be revoked."))}</p></div>${lifecycle}</div></div></div></section>`
  } else if (view === "login-methods") {
    const passwords = data.passwords ?? []
    const passkeys = data.passkeys ?? []
    const minimum = data.passwordMinimum ?? 6
    const feedback = data.feedback?.view === "login-methods" ? data.feedback : undefined
    const passwordError = feedback?.field === "password" ? feedback.error : undefined
    const methodRows = [
      ...passwords.map((password) => [
        `<span class="method-label">${escapeHtml(i18n.t("Password"))}</span>`,
        `<b>${escapeHtml(password.name ?? i18n.t("Password"))}</b>${minimum === 12 && !password.adminEligible ? `<p class="form-hint">${escapeHtml(i18n.t("Unavailable while this user is an administrator"))}</p>` : ""}`,
        password.lastUsedAt === null
          ? escapeHtml(i18n.t("Never"))
          : `<span class="mono">${escapeHtml(fmtDate(i18n, password.lastUsedAt))}</span>`,
        `<span class="mono">${escapeHtml(fmtDate(i18n, password.createdAt))}</span>`,
        `<a class="btn btn--danger btn--tiny" href="/console/users/${escapeHtml(user.id)}/passwords/${escapeHtml(password.id)}/delete">${escapeHtml(i18n.t("Remove login method"))}</a>`,
      ]),
      ...passkeys.map((passkey) => [
        `<span class="method-label method-label--passkey">${escapeHtml(i18n.t("Passkey"))}</span>`,
        `<b>${escapeHtml(passkey.name ?? i18n.t("Passkey"))}</b>`,
        passkey.lastUsedAt === null
          ? escapeHtml(i18n.t("Never"))
          : `<span class="mono">${escapeHtml(fmtDate(i18n, passkey.lastUsedAt))}</span>`,
        `<span class="mono">${escapeHtml(fmtDate(i18n, passkey.createdAt))}</span>`,
        `<a class="btn btn--danger btn--tiny" href="/console/users/${escapeHtml(user.id)}/passkeys/${escapeHtml(passkey.id)}/delete">${escapeHtml(i18n.t("Remove login method"))}</a>`,
      ]),
    ]
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Login methods"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Passwords, passkeys, and one-time sign-in links."))}</p></div><span class="badge">${escapeHtml(i18n.t("{count} total", { count: methodRows.length }))}</span></div>${dataTable(i18n, ["Type", "Name", "Last used", "Created", ""], methodRows, "No password or passkey has been configured.")}<div class="panel__body">${detailAlert(i18n, feedback)}<form method="post" action="/console/users/${escapeHtml(user.id)}/passwords" class="form-grid form-grid--method">${csrfField(csrfToken)}${textField(i18n, "Password name", "name", feedback?.values.passwordName ?? "", { placeholder: "e.g. Temporary password" })}${textField(i18n, "New password", "password", "", { type: "password", required: true, error: passwordError })}${textField(i18n, "Confirm password", "password_confirm", "", { type: "password", required: true, error: passwordError })}<p class="form-hint form-hint--standalone">${escapeHtml(i18n.t("Requires {minimum}–128 characters for this user. Password values are never shown again.", { minimum }))}</p><div><button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Add password"))}</button></div></form><div class="action-list"><div class="action-row"><div><h3>${escapeHtml(i18n.t("Magic link"))}</h3><p>${escapeHtml(i18n.t("Generate a one-time 15-minute sign-in link for this existing user."))}</p></div><form method="post" action="/console/users/${escapeHtml(user.id)}/magic-link">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit"${user.disabled ? " disabled" : ""}>${escapeHtml(i18n.t("Generate magic link"))}</button></form></div></div></div></section>`
  } else if (view === "access") {
    const groups = data.groups ?? []
    const selected = data.selectedGroupIds ?? new Set<string>()
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Access"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Permission-group membership for this user."))}</p></div></div><div class="panel__body"><form method="post" action="/console/users/${escapeHtml(user.id)}/groups" class="form-grid">${csrfField(csrfToken)}<div class="field--wide">${groupChoices(i18n, groups, selected)}</div><div class="form-actions"><button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Update groups"))}</button></div></form></div></section>`
  } else {
    const sessions = data.sessions ?? []
    const rows = sessions.map((session) => [
      escapeHtml(
        i18n.t(
          session.authMethod === "magic_link"
            ? "Magic link"
            : session.authMethod === "passkey"
              ? "Passkey"
              : "Password",
        ),
      ),
      `<span class="mono">${escapeHtml(i18n.formatDateTime(session.createdAt))}</span>`,
      `<span class="mono">${escapeHtml(i18n.formatDateTime(session.lastSeenAt))}</span>`,
      `<span class="mono">${escapeHtml(i18n.formatDateTime(session.expiresAt))}</span>`,
    ])
    const action =
      sessions.length === 0
        ? ""
        : `<div class="panel__body"><a class="btn btn--danger btn--auto" href="/console/users/${escapeHtml(user.id)}/revoke-sessions">${escapeHtml(i18n.t("Revoke all sessions"))}</a></div>`
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Sessions"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Active browser sessions for this user."))}</p></div></div>${dataTable(i18n, ["Authentication", "Started", "Last active", "Expires"], rows, "No active sessions.")}${action}</section>`
  }
  return consoleShell(user.email, chrome, `${summary}${panel}`)
}

export type UserAction = "disable" | "delete-password" | "delete-passkey" | "revoke-sessions"

export function renderUserActionConfirmation(
  chrome: ConsoleChrome,
  user: User,
  csrfToken: string,
  action: UserAction,
  target?: { readonly id: string; readonly name: string },
): string {
  const { i18n } = chrome
  const config =
    action === "disable"
      ? {
          title: "Disable user?",
          consequence: "This immediately revokes every session and refresh token for this user.",
          endpoint: `/console/users/${escapeHtml(user.id)}/disable`,
          label: "Disable user",
          cancelView: "profile" as UserDetailView,
        }
      : action === "revoke-sessions"
        ? {
            title: "Revoke all sessions?",
            consequence: "Every active browser session for this user will be revoked.",
            endpoint: `/console/users/${escapeHtml(user.id)}/revoke-sessions`,
            label: "Revoke all sessions",
            cancelView: "sessions" as UserDetailView,
          }
        : {
            title: "Remove login method?",
            consequence:
              "The user will no longer be able to sign in with this method. At least one login method must remain.",
            endpoint: `/console/users/${escapeHtml(user.id)}/${action === "delete-password" ? "passwords" : "passkeys"}/${escapeHtml(target?.id ?? "")}/delete`,
            label: "Remove login method",
            cancelView: "login-methods" as UserDetailView,
          }
  const targetHtml =
    target === undefined
      ? ""
      : `<div class="callout"><strong>${escapeHtml(target.name)}</strong></div>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t(config.title))}</h2><p class="panel__desc">${escapeHtml(user.email)}</p></div><a class="btn btn--ghost btn--sm back-link" href="${escapeHtml(userHref(user.id, config.cancelView))}">${escapeHtml(i18n.t("Back to user"))}</a></div><section class="panel"><div class="panel__body">${targetHtml}<div class="callout">${escapeHtml(i18n.t(config.consequence))}</div><form method="post" action="${config.endpoint}" class="form-grid form-grid--single">${csrfField(csrfToken)}<div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t(config.label))}</button></div></form></div></section>`
  return consoleShell(i18n.t(config.title), chrome, content)
}

export function renderMagicLinkResult(chrome: ConsoleChrome, user: User, url: string): string {
  const { i18n } = chrome
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Magic link generated"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("One-time sign-in for {email}.", { email: user.email }))}</p></div><a class="btn btn--ghost btn--sm back-link" href="${escapeHtml(userHref(user.id, "login-methods"))}">${escapeHtml(i18n.t("Back to user"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Share this link securely"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("It expires in 15 minutes and can be used only once. Creating another security transition invalidates it."))}</p></div></div><div class="panel__body"><div class="copy-value"><code class="secret copy-value__text" data-copy-source>${escapeHtml(url)}</code><button class="btn btn--ghost btn--tiny" type="button" data-copy-value data-copy-success="${escapeHtml(i18n.t("Magic link copied."))}" hidden>${escapeHtml(i18n.t("Copy"))}</button><span class="copy-value__status" data-copy-status role="status" hidden></span></div><p class="form-hint">${escapeHtml(i18n.t("The link is intentionally shown only on this page."))}</p></div></section>`
  return consoleShell(i18n.t("Magic link"), chrome, content)
}
