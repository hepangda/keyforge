import type { PasswordCredentialSummary } from "../../auth/password"
import type { GroupSummary } from "../../db/queries/users"
import type { CredentialSummary } from "../../db/queries/webauthn"
import type { I18n } from "../../i18n"
import type { User } from "../../types/domain"
import { escapeHtml } from "../layout"
import {
  checkboxField,
  csrfField,
  dataTable,
  fmtDate,
  pager,
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
    return `<p class="form-hint">${escapeHtml(i18n.t("No groups exist yet. Create one from the user directory."))}</p>`
  }
  return `<div class="group-choice-grid">${groups
    .map(
      (group) => `<label class="group-choice">
        <input type="checkbox" name="group_ids" value="${escapeHtml(group.id)}"${selectedIds.has(group.id) ? " checked" : ""}>
        <span><b>${escapeHtml(group.name)}</b><small>${escapeHtml(group.description ?? i18n.t("No description"))}</small></span>
      </label>`,
    )
    .join("")}</div>`
}

export function renderUsersList(
  chrome: ConsoleChrome,
  users: readonly User[],
  groups: readonly GroupSummary[],
  csrfToken: string,
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
  const groupRows = groups.map((group) => [
    `<span class="tag">${escapeHtml(group.name)}</span>`,
    String(group.memberCount),
    `<form method="post" action="/console/groups/${encodeURIComponent(group.id)}" class="actions">
      ${csrfField(csrfToken)}
      <input class="input input--compact" name="name" value="${escapeHtml(group.name)}" required maxlength="64" aria-label="${escapeHtml(i18n.t("Group name"))}">
      <input class="input input--compact" name="description" value="${escapeHtml(group.description ?? "")}" maxlength="500" aria-label="${escapeHtml(i18n.t("Group description"))}">
      <button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Save"))}</button>
    </form>
    ${group.name === "admins" ? `<span class="form-hint">${escapeHtml(i18n.t("Protected"))}</span>` : `<div class="actions"><a class="btn btn--danger btn--tiny" href="/console/groups/${encodeURIComponent(group.id)}/delete">${escapeHtml(i18n.t("Delete"))}</a></div>`}`,
  ])
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(i18n.t("Identity directory"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Create accounts, invite people, and assign access groups."))}</p></div>
    <a class="btn btn--primary btn--sm" href="/console/users/new">${escapeHtml(i18n.t("Add user"))}</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Users"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Everyone who can sign in to this server."))}</p></div></div>
    ${dataTable(i18n, ["Username", "Email", "Status", "Created", ""], userRows, "No users found. Add the first account to begin.")}
    <div class="panel__body">${pager(i18n, "/console/users", limit, offset, users.length, hasNext)}</div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Permission groups"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Use groups to grant application and administrator claims."))}</p></div></div>
    ${dataTable(i18n, ["Group", "Members", "Manage"], groupRows, "No groups found. Create one below.")}
    <div class="panel__body">
      <form method="post" action="/console/groups" class="form-grid form-grid--inline">
        ${csrfField(csrfToken)}
        ${textField(i18n, "Group name", "name", "", { required: true, placeholder: "support-agents" })}
        ${textField(i18n, "Description", "description", "", { placeholder: "What membership grants" })}
        <div><button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Create group"))}</button></div>
      </form>
    </div>
  </section>`
  return consoleShell(i18n.t("Users"), chrome, content)
}

export function renderGroupDeleteConfirmation(
  chrome: ConsoleChrome,
  group: GroupSummary,
  csrfToken: string,
  error?: string,
): string {
  const { i18n } = chrome
  const id = encodeURIComponent(group.id)
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(error))}</div>`
  const memberSummary = i18n.t(
    group.memberCount === 1
      ? "{group} currently has {count} member."
      : "{group} currently has {count} members.",
    { group: group.name, count: group.memberCount },
  )
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(i18n.t("Delete permission group?"))}</h2><p class="panel__desc">${escapeHtml(memberSummary)}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/users">${escapeHtml(i18n.t("Cancel"))}</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Confirm group deletion"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("This permanently removes the group and every membership assignment. User accounts are not deleted."))}</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/groups/${id}/delete" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField(i18n, i18n.t("Type {value} to confirm", { value: group.name }), "confirmation", "", { required: true })}
        <div><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Delete group"))}</button></div>
      </form>
    </div>
  </section>`
  return consoleShell(i18n.t("Delete group?"), chrome, content)
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
  }
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(i18n.t("Add a user"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Give someone a direct credential or send a single-use invitation."))}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/users">${escapeHtml(i18n.t("Back to users"))}</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Account details"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Leaving the password blank sends a secure one-hour invitation link."))}</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/users" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField(i18n, "Email", "email", values.email, { type: "email", required: true, placeholder: "name@example.com" })}
        ${textField(i18n, "Username", "alias", values.alias, { required: true, placeholder: "janedoe" })}
        <p class="form-hint form-hint--standalone">${escapeHtml(i18n.t("English letters and numbers only; usernames are unique and can be used at sign-in."))}</p>
        ${textField(i18n, "Display name", "name", values.name, { placeholder: "Optional" })}
        ${textField(i18n, "Initial password", "password", "", { type: "password", placeholder: "Leave blank to send an invitation" })}
        <p class="form-hint form-hint--standalone">${escapeHtml(i18n.t("Initial passwords require 6–128 characters, or at least 12 when the admins group is selected. Invitations never expose a credential to the administrator."))}</p>
        ${checkboxField(i18n, "Mark email as verified", "email_verified", values.emailVerified)}
        <fieldset class="field-cluster"><legend>${escapeHtml(i18n.t("Groups"))}</legend>${groupChoices(i18n, groups, new Set(values.groupIds))}</fieldset>
        <div><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Create user"))}</button></div>
      </form>
    </div>
  </section>`
  return consoleShell(i18n.t("Add user"), chrome, content)
}

export type UserCreateValues = {
  readonly email: string
  readonly alias: string
  readonly name: string
  readonly emailVerified: boolean
  readonly groupIds: readonly string[]
}

export type UserCreateFeedback = {
  readonly values: UserCreateValues
  readonly error: string
}

export function renderUserDetail(
  chrome: ConsoleChrome,
  user: User,
  groups: readonly GroupSummary[],
  selectedGroupIds: ReadonlySet<string>,
  passwords: readonly PasswordCredentialSummary[],
  passkeys: readonly CredentialSummary[],
  passwordMinimum: number,
  csrfToken: string,
): string {
  const { i18n } = chrome
  const selectedNames = groups
    .filter((group) => selectedGroupIds.has(group.id))
    .map((group) => `<span class="tag">${escapeHtml(group.name)}</span>`)
    .join("")
  const groupList = selectedNames === "" ? '<span class="mono">—</span>' : selectedNames
  const methodRows = [
    ...passwords.map((password) => [
      `<span class="method-label">${escapeHtml(i18n.t("Password"))}</span>`,
      `<b>${escapeHtml(password.name ?? i18n.t("Password"))}</b>${passwordMinimum === 12 && !password.adminEligible ? `<p class="form-hint">${escapeHtml(i18n.t("Unavailable while this user is an administrator"))}</p>` : ""}`,
      password.lastUsedAt === null
        ? escapeHtml(i18n.t("Never"))
        : `<span class="mono">${escapeHtml(fmtDate(i18n, password.lastUsedAt))}</span>`,
      `<span class="mono">${escapeHtml(fmtDate(i18n, password.createdAt))}</span>`,
      `<form method="post" action="/console/users/${escapeHtml(user.id)}/passwords/${escapeHtml(password.id)}/delete" class="actions">${csrfField(csrfToken)}<button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Delete"))}</button></form>`,
    ]),
    ...passkeys.map((passkey) => [
      `<span class="method-label method-label--passkey">${escapeHtml(i18n.t("Passkey"))}</span>`,
      `<b>${escapeHtml(passkey.name ?? i18n.t("Passkey"))}</b>`,
      passkey.lastUsedAt === null
        ? escapeHtml(i18n.t("Never"))
        : `<span class="mono">${escapeHtml(fmtDate(i18n, passkey.lastUsedAt))}</span>`,
      `<span class="mono">${escapeHtml(fmtDate(i18n, passkey.createdAt))}</span>`,
      `<form method="post" action="/console/users/${escapeHtml(user.id)}/passkeys/${escapeHtml(passkey.id)}/delete" class="actions">${csrfField(csrfToken)}<button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Delete"))}</button></form>`,
    ]),
  ]
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(user.name ?? user.alias)}</h2><p class="panel__desc"><span class="mono">@${escapeHtml(user.alias)}</span> · ${escapeHtml(user.email)}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/users">${escapeHtml(i18n.t("Back to users"))}</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Profile"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Groups:"))} ${groupList}</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField(i18n, "Username", "alias", user.alias, { required: true })}
        <p class="form-hint form-hint--standalone">${escapeHtml(i18n.t("English letters and numbers only. Users can sign in with this username."))}</p>
        ${textField(i18n, "Display name", "name", user.name ?? "", { placeholder: "No name set" })}
        ${checkboxField(i18n, "Email verified", "email_verified", user.emailVerified)}
        ${checkboxField(i18n, "Account disabled (blocks sign-in)", "disabled", user.disabled)}
        <div><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button></div>
      </form>
    </div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Login methods"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Passwords and passkeys are managed together. Keep at least one reusable method."))}</p></div><span class="badge">${escapeHtml(i18n.t("{count} total", { count: methodRows.length }))}</span></div>
    ${dataTable(i18n, ["Type", "Name", "Last used", "Created", ""], methodRows, "No password or passkey has been configured.")}
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}/passwords" class="form-grid form-grid--method">
        ${csrfField(csrfToken)}
        ${textField(i18n, "Password name", "name", "", { placeholder: "e.g. Temporary password" })}
        ${textField(i18n, "New password", "password", "", { type: "password", required: true })}
        ${textField(i18n, "Confirm password", "password_confirm", "", { type: "password", required: true })}
        <p class="form-hint form-hint--standalone">${escapeHtml(i18n.t("Requires {minimum}–128 characters for this user. Password values are never shown again.", { minimum: passwordMinimum }))}</p>
        <div><button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Add password"))}</button></div>
      </form>
    </div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Magic link"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Generate a one-time 15-minute sign-in link for this existing user."))}</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}/magic-link">
        ${csrfField(csrfToken)}
        <button class="btn btn--ghost btn--auto" type="submit"${user.disabled ? " disabled" : ""}>${escapeHtml(i18n.t("Generate magic link"))}</button>
      </form>
      ${user.disabled ? `<p class="form-hint">${escapeHtml(i18n.t("Enable this user before generating a sign-in link."))}</p>` : ""}
    </div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Group access"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Administrator access comes from the admins group. The last active administrator cannot remove it."))}</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}/groups" class="form-grid">
        ${csrfField(csrfToken)}
        ${groupChoices(i18n, groups, selectedGroupIds)}
        <div><button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Update groups"))}</button></div>
      </form>
    </div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Sessions"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Force sign-out on every device this user is signed in on."))}</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}/revoke-sessions">
        ${csrfField(csrfToken)}
        <button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Revoke all sessions"))}</button>
      </form>
    </div>
  </section>`
  return consoleShell(user.email, chrome, content)
}

export function renderMagicLinkResult(chrome: ConsoleChrome, user: User, url: string): string {
  const { i18n } = chrome
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Magic link generated"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("One-time sign-in for {email}.", { email: user.email }))}</p></div><a class="btn btn--ghost btn--sm" href="/console/users/${escapeHtml(user.id)}">${escapeHtml(i18n.t("Back to user"))}</a></div>
  <section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Share this link securely"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("It expires in 15 minutes and can be used only once. Creating another security transition invalidates it."))}</p></div></div><div class="panel__body"><div class="secret">${escapeHtml(url)}</div><p class="form-hint">${escapeHtml(i18n.t("The link is intentionally shown only on this page."))}</p></div></section>`
  return consoleShell(i18n.t("Magic link"), chrome, content)
}
