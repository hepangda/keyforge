import type { GroupSummary } from "../../db/queries/users"
import type { User, UserType } from "../../types/domain"
import { escapeHtml } from "../layout"
import {
  checkboxField,
  csrfField,
  dataTable,
  fmtDate,
  pager,
  selectField,
  statusBadge,
  textField,
} from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

function groupChoices(groups: readonly GroupSummary[], selectedIds: ReadonlySet<string>): string {
  if (groups.length === 0) {
    return '<p class="form-hint">No groups exist yet. Create one from the user directory.</p>'
  }
  return `<div class="group-choice-grid">${groups
    .map(
      (group) => `<label class="group-choice">
        <input type="checkbox" name="group_ids" value="${escapeHtml(group.id)}"${selectedIds.has(group.id) ? " checked" : ""}>
        <span><b>${escapeHtml(group.name)}</b><small>${escapeHtml(group.description ?? "No description")}</small></span>
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
  const userRows = users.map((user) => [
    `<b>${escapeHtml(user.email)}</b>`,
    escapeHtml(user.userType === "internal" ? "Internal" : "External"),
    statusBadge(!user.disabled, "Active", "Disabled"),
    `<span class="mono">${escapeHtml(fmtDate(user.createdAt))}</span>`,
    `<div class="actions"><a class="btn btn--ghost btn--tiny" href="/console/users/${escapeHtml(user.id)}">Manage</a></div>`,
  ])
  const groupRows = groups.map((group) => [
    `<span class="tag">${escapeHtml(group.name)}</span>`,
    String(group.memberCount),
    `<form method="post" action="/console/groups/${encodeURIComponent(group.id)}" class="actions">
      ${csrfField(csrfToken)}
      <input class="input input--compact" name="name" value="${escapeHtml(group.name)}" required maxlength="64" aria-label="Group name">
      <input class="input input--compact" name="description" value="${escapeHtml(group.description ?? "")}" maxlength="500" aria-label="Group description">
      <button class="btn btn--ghost btn--tiny" type="submit">Save</button>
    </form>
    ${group.name === "admins" ? '<span class="form-hint">Protected</span>' : `<div class="actions"><a class="btn btn--danger btn--tiny" href="/console/groups/${encodeURIComponent(group.id)}/delete">Delete</a></div>`}`,
  ])
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">Identity directory</h2><p class="panel__desc">Create accounts, invite people, and assign access groups.</p></div>
    <a class="btn btn--primary btn--sm" href="/console/users/new">Add user</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Users</h2><p class="panel__desc">Everyone who can sign in to this server.</p></div></div>
    ${dataTable(["Email", "Type", "Status", "Created", ""], userRows, "No users found. Add the first account to begin.")}
    <div class="panel__body">${pager("/console/users", limit, offset, users.length, hasNext)}</div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Permission groups</h2><p class="panel__desc">Use groups to grant application and administrator claims.</p></div></div>
    ${dataTable(["Group", "Members", "Manage"], groupRows, "No groups found. Create one below.")}
    <div class="panel__body">
      <form method="post" action="/console/groups" class="form-grid form-grid--inline">
        ${csrfField(csrfToken)}
        ${textField("Group name", "name", "", { required: true, placeholder: "support-agents" })}
        ${textField("Description", "description", "", { placeholder: "What membership grants" })}
        <div><button class="btn btn--ghost btn--auto" type="submit">Create group</button></div>
      </form>
    </div>
  </section>`
  return consoleShell("Users — Admin console", chrome, content)
}

export function renderGroupDeleteConfirmation(
  chrome: ConsoleChrome,
  group: GroupSummary,
  csrfToken: string,
  error?: string,
): string {
  const id = encodeURIComponent(group.id)
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(error)}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">Delete permission group?</h2><p class="panel__desc"><span class="mono">${escapeHtml(group.name)}</span> currently has ${group.memberCount} member${group.memberCount === 1 ? "" : "s"}.</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/users">Cancel</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Confirm group deletion</h2><p class="panel__desc">This permanently removes the group and every membership assignment. User accounts are not deleted.</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/groups/${id}/delete" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField(`Type ${group.name} to confirm`, "confirmation", "", { required: true })}
        <div><button class="btn btn--danger btn--auto" type="submit">Delete group</button></div>
      </form>
    </div>
  </section>`
  return consoleShell("Delete group? — Admin console", chrome, content)
}

export function renderUserCreate(
  chrome: ConsoleChrome,
  groups: readonly GroupSummary[],
  csrfToken: string,
  feedback?: UserCreateFeedback,
): string {
  const values = feedback?.values ?? {
    email: "",
    name: "",
    userType: "external" as const,
    emailVerified: false,
    groupIds: [],
  }
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(feedback.error)}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">Add a user</h2><p class="panel__desc">Give someone a direct credential or send a single-use invitation.</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/users">Back to users</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Account details</h2><p class="panel__desc">Leaving the password blank sends a secure one-hour invitation link.</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/users" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField("Email", "email", values.email, { type: "email", required: true, placeholder: "name@example.com" })}
        ${textField("Display name", "name", values.name, { placeholder: "Optional" })}
        ${selectField(
          "Account type",
          "user_type",
          [
            { value: "external", label: "External" },
            { value: "internal", label: "Internal" },
          ],
          values.userType,
        )}
        ${textField("Initial password", "password", "", { type: "password", placeholder: "Leave blank to send an invitation" })}
        <p class="form-hint form-hint--standalone">Initial passwords require 12–128 characters. Invitations never expose a credential to the administrator.</p>
        ${checkboxField("Mark email as verified", "email_verified", values.emailVerified)}
        <fieldset class="field-cluster"><legend>Groups</legend>${groupChoices(groups, new Set(values.groupIds))}</fieldset>
        <div><button class="btn btn--primary btn--auto" type="submit">Create user</button></div>
      </form>
    </div>
  </section>`
  return consoleShell("Add user — Admin console", chrome, content)
}

export type UserCreateValues = {
  readonly email: string
  readonly name: string
  readonly userType: UserType
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
  csrfToken: string,
): string {
  const selectedNames = groups
    .filter((group) => selectedGroupIds.has(group.id))
    .map((group) => `<span class="tag">${escapeHtml(group.name)}</span>`)
    .join("")
  const groupList = selectedNames === "" ? '<span class="mono">—</span>' : selectedNames
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(user.email)}</h2><p class="panel__desc mono">${escapeHtml(user.id)}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/users">Back to users</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Profile</h2><p class="panel__desc">Groups: ${groupList}</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField("Display name", "name", user.name ?? "", { placeholder: "No name set" })}
        ${selectField(
          "Account type",
          "user_type",
          [
            { value: "internal", label: "Internal" },
            { value: "external", label: "External" },
          ],
          user.userType,
        )}
        ${checkboxField("Email verified", "email_verified", user.emailVerified)}
        ${checkboxField("Account disabled (blocks sign-in)", "disabled", user.disabled)}
        <div><button class="btn btn--primary btn--auto" type="submit">Save changes</button></div>
      </form>
    </div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Group access</h2><p class="panel__desc">Administrator access comes from the <span class="mono">admins</span> group. The last active administrator cannot remove it.</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}/groups" class="form-grid">
        ${csrfField(csrfToken)}
        ${groupChoices(groups, selectedGroupIds)}
        <div><button class="btn btn--ghost btn--auto" type="submit">Update groups</button></div>
      </form>
    </div>
  </section>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Sessions</h2><p class="panel__desc">Force sign-out on every device this user is signed in on.</p></div></div>
    <div class="panel__body">
      <form method="post" action="/console/users/${escapeHtml(user.id)}/revoke-sessions">
        ${csrfField(csrfToken)}
        <button class="btn btn--danger btn--auto" type="submit">Revoke all sessions</button>
      </form>
    </div>
  </section>`
  return consoleShell(`${user.email} — Admin console`, chrome, content)
}
