import type {
  GroupMemberCandidate,
  GroupMemberSummary,
  GroupMembershipRequestSummary,
} from "../../db/queries/group-memberships"
import type { GroupSummary } from "../../db/queries/users"
import type { I18n } from "../../i18n"
import type { PermissionGroupRule } from "../../oauth/permission-rules"
import { isPermissionGroupControlledScope } from "../../oauth/scope-policy"
import type { OAuthClient, OAuthResource } from "../../types/domain"
import { escapeHtml } from "../layout"
import {
  csrfField,
  dataTable,
  fmtDateTime,
  pager,
  secondaryTabs,
  statusBadge,
  textField,
} from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

export type GroupFormValues = {
  readonly name: string
  readonly description: string
  readonly visibility: "public" | "hidden"
  readonly priority: string
}

export type GroupFormFeedback = {
  readonly values: GroupFormValues
  readonly field: "name" | "description" | "priority" | null
  readonly error: string
}

export type GroupDetailView = "settings" | "access" | "members"

export type GroupDetailData = {
  readonly group: GroupSummary
  readonly view: GroupDetailView
  readonly csrfToken: string
  readonly clients?: readonly OAuthClient[]
  readonly resources?: readonly OAuthResource[]
  readonly rules?: readonly PermissionGroupRule[]
  readonly rulesJson?: string
  readonly settingsFeedback?: GroupFormFeedback
  readonly accessError?: string
  readonly members?: readonly GroupMemberSummary[]
  readonly membershipRequests?: readonly GroupMembershipRequestSummary[]
  readonly memberCandidates?: readonly GroupMemberCandidate[]
  readonly memberQuery?: string
  readonly memberLimit?: number
  readonly memberOffset?: number
  readonly memberHasNext?: boolean
}

function errorSummary(i18n: I18n, error: string | undefined): string {
  return error === undefined
    ? ""
    : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(error))}</div>`
}

function configurableScopeCatalog(
  resources: readonly OAuthResource[],
): readonly { readonly value: string; readonly apiNames: readonly string[] }[] {
  const apiNamesByScope = new Map<string, Set<string>>()
  for (const resource of resources) {
    for (const scope of resource.allowedScopes.filter(isPermissionGroupControlledScope)) {
      const apiNames = apiNamesByScope.get(scope) ?? new Set<string>()
      apiNames.add(resource.name)
      apiNamesByScope.set(scope, apiNames)
    }
  }
  return [...apiNamesByScope.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([value, apiNames]) => ({ value, apiNames: [...apiNames].sort() }))
}

function ruleCatalog(
  i18n: I18n,
  clients: readonly OAuthClient[],
  resources: readonly OAuthResource[],
): string {
  const applicationItems = clients
    .map(
      (client) =>
        `<li><code>${escapeHtml(client.clientId)}</code> — ${escapeHtml(client.name)}</li>`,
    )
    .join("")
  const apiItems = resources
    .map(
      (resource) =>
        `<li><code>${escapeHtml(resource.resourceUri)}</code> — ${escapeHtml(resource.name)}</li>`,
    )
    .join("")
  const scopeItems = configurableScopeCatalog(resources)
    .map(
      (scope) =>
        `<li><code>${escapeHtml(scope.value)}</code> — ${escapeHtml(scope.apiNames.join(" · "))}</li>`,
    )
    .join("")
  const empty = `<li>${escapeHtml(i18n.t("None available"))}</li>`
  return `<details class="permission-rule-catalog field--wide"><summary>${escapeHtml(i18n.t("Available rule values"))}</summary><div class="form-grid"><div><h3>${escapeHtml(i18n.t("Applications and devices"))}</h3><ul class="form-hint">${applicationItems || empty}</ul></div><div><h3>${escapeHtml(i18n.t("APIs"))}</h3><ul class="form-hint">${apiItems || empty}</ul></div><div><h3>${escapeHtml(i18n.t("Configurable scopes"))}</h3><ul class="form-hint">${scopeItems || empty}</ul></div></div></details>`
}

function visibilityChoices(i18n: I18n, selected: "public" | "hidden"): string {
  return `<fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Request visibility"))}</legend><div class="choice-cards choice-cards--two"><label class="choice-card"><input type="radio" name="visibility" value="public"${selected === "public" ? " checked" : ""} required><b>${escapeHtml(i18n.t("Public group"))}</b><small>${escapeHtml(i18n.t("Listed in the request directory and searchable by name or description."))}</small></label><label class="choice-card"><input type="radio" name="visibility" value="hidden"${selected === "hidden" ? " checked" : ""} required><b>${escapeHtml(i18n.t("Hidden group"))}</b><small>${escapeHtml(i18n.t("Not listed; users must enter the complete group name exactly."))}</small></label></div></fieldset>`
}

export function renderGroupsList(chrome: ConsoleChrome, groups: readonly GroupSummary[]): string {
  const { i18n } = chrome
  const rows = groups.map((group) => {
    const protectedGroup = group.name === "admins" || group.name === "all"
    const href = `/console/groups/${encodeURIComponent(group.id)}${protectedGroup ? "?view=access" : ""}`
    return [
      `<span class="tag">${escapeHtml(group.name)}</span>`,
      escapeHtml(group.description ?? i18n.t("No description")),
      `<span class="mono">${escapeHtml(String(group.priority))}</span>`,
      statusBadge(i18n, group.isPublic, "Public group", "Hidden group"),
      String(group.memberCount),
      `<div class="actions">${protectedGroup ? `<span class="form-hint">${escapeHtml(i18n.t("Protected"))}</span>` : ""}<a class="btn btn--ghost btn--tiny" href="${href}">${escapeHtml(i18n.t("Manage"))}</a></div>`,
    ]
  })
  const emptyAction =
    groups.length === 0
      ? `<div class="panel__body"><a class="btn btn--primary btn--auto" href="/console/groups/new">${escapeHtml(i18n.t("Create a group"))}</a></div>`
      : ""
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Permission groups"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Assign memberships and evaluate ordered application, API, and scope rules."))}</p></div><a class="btn btn--primary btn--sm" href="/console/groups/new">${escapeHtml(i18n.t("Create a group"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Permission groups"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Smaller priority numbers win; deny wins ties."))}</p></div></div>${dataTable(i18n, ["Group", "Description", "Priority", "Visibility", "Members", ""], rows, "No groups found. Create the first group to begin.")}${emptyAction}</section>`
  return consoleShell(i18n.t("Permission groups"), chrome, content)
}

export function renderGroupCreateForm(
  chrome: ConsoleChrome,
  csrfToken: string,
  feedback?: GroupFormFeedback,
): string {
  const { i18n } = chrome
  const values = feedback?.values ?? {
    name: "",
    description: "",
    visibility: "public",
    priority: "0",
  }
  const visibility = visibilityChoices(i18n, values.visibility)
  const priority = `<label class="field"><span class="field__label">${escapeHtml(i18n.t("Priority"))}</span><input class="input" type="number" name="priority" min="0" max="1000000" step="1" value="${escapeHtml(values.priority)}" required${feedback?.field === "priority" ? ' aria-invalid="true"' : ""}><p class="form-hint">${escapeHtml(i18n.t("Like nice values, smaller numbers have higher priority."))}</p></label>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Create a group"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Create an ordered rule container. Rules are configured after creation."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups">${escapeHtml(i18n.t("Back to groups"))}</a></div><section class="panel"><div class="panel__body">${errorSummary(i18n, feedback?.error)}<form method="post" action="/console/groups" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Group name", "name", values.name, { required: true, placeholder: "support-agents", error: feedback?.field === "name" ? feedback.error : undefined })}${textField(i18n, "Description", "description", values.description, { placeholder: "What membership grants", error: feedback?.field === "description" ? feedback.error : undefined })}${priority}${visibility}<div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Create group"))}</button></div></form></div></section>`
  return consoleShell(i18n.t("Create a group"), chrome, content)
}

export function renderGroupDetail(chrome: ConsoleChrome, data: GroupDetailData): string {
  const { i18n } = chrome
  const { group, view, csrfToken } = data
  const id = encodeURIComponent(group.id)
  const tabs = secondaryTabs(i18n, "Group sections", [
    { label: "Settings", href: `/console/groups/${id}?view=settings`, active: view === "settings" },
    { label: "Access", href: `/console/groups/${id}?view=access`, active: view === "access" },
    { label: "Members", href: `/console/groups/${id}?view=members`, active: view === "members" },
  ])
  const summary = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(group.name)}</h2><p class="panel__desc">${escapeHtml(i18n.t("Membership activates this group's rules; access still requires matching allow rules."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups">${escapeHtml(i18n.t("Back to groups"))}</a></div>${tabs}`
  let panel: string
  if (view === "settings") {
    const protectedGroup = group.name === "admins" || group.name === "all"
    const values = data.settingsFeedback?.values ?? {
      name: group.name,
      description: group.description ?? "",
      visibility: group.isPublic ? "public" : "hidden",
      priority: String(group.priority),
    }
    const priority = `<label class="field"><span class="field__label">${escapeHtml(i18n.t("Priority"))}</span><input class="input" type="number" name="priority" min="0" max="1000000" step="1" value="${escapeHtml(values.priority)}" required${data.settingsFeedback?.field === "priority" ? ' aria-invalid="true"' : ""}><p class="form-hint">${escapeHtml(i18n.t("Like nice values, smaller numbers have higher priority."))}</p></label>`
    const deleteAction = protectedGroup
      ? `<span class="form-hint">${escapeHtml(i18n.t("Built-in permission groups cannot be deleted or renamed."))}</span>`
      : `<a class="btn btn--danger btn--auto" href="/console/groups/${id}/delete">${escapeHtml(i18n.t("Delete group"))}</a>`
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Settings"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Name, priority, description, and request visibility for this permission group."))}</p></div></div><div class="panel__body">${errorSummary(i18n, data.settingsFeedback?.error)}<form method="post" action="/console/groups/${id}/settings" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Group name", "name", values.name, { required: true, readonly: protectedGroup, placeholder: "support-agents", error: data.settingsFeedback?.field === "name" ? data.settingsFeedback.error : undefined })}${textField(i18n, "Description", "description", values.description, { placeholder: "What membership grants", error: data.settingsFeedback?.field === "description" ? data.settingsFeedback.error : undefined })}${priority}${visibilityChoices(i18n, values.visibility)}<div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button>${deleteAction}</div></form></div></section>`
  } else if (view === "access") {
    const rulesJson = data.rulesJson ?? JSON.stringify(data.rules ?? [], null, 2)
    const clients = data.clients ?? []
    const resources = data.resources ?? []
    const configurableScopes = configurableScopeCatalog(resources)
    const catalog = ruleCatalog(i18n, clients, resources)
    const editorCatalog = JSON.stringify({
      application: clients.map((client) => ({ value: client.clientId, label: client.name })),
      api: resources.map((resource) => ({ value: resource.resourceUri, label: resource.name })),
      scope: configurableScopes.map((scope) => ({
        value: scope.value,
        label: scope.value,
        detail: scope.apiNames.join(" · "),
      })),
    })
    panel = `<section class="panel panel--rule-editor"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Rules"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Rules match the application, API, and scope authorization context."))}</p></div><span class="badge">${escapeHtml(i18n.t("Priority {priority}", { priority: group.priority }))}</span></div><div class="panel__body">${errorSummary(i18n, data.accessError)}<p class="form-hint">${escapeHtml(i18n.t("Rules without a scope condition decide base application/API access. Custom scopes require a separate matching allow rule. Smaller priority numbers win; deny wins ties."))}</p>${catalog}<form method="post" action="/console/groups/${id}/access" class="form-grid">${csrfField(csrfToken)}<div class="field--wide permission-rule-editor" data-permission-rule-editor data-catalog="${escapeHtml(editorCatalog)}" data-add-rule-label="${escapeHtml(i18n.t("Add rule"))}" data-remove-label="${escapeHtml(i18n.t("Remove"))}" data-add-condition-label="${escapeHtml(i18n.t("Add condition"))}" data-rule-label="${escapeHtml(i18n.t("Rule"))}" data-condition-label="${escapeHtml(i18n.t("Condition"))}" data-empty-label="${escapeHtml(i18n.t("No rules configured. Access is denied by default."))}" data-search-application-label="${escapeHtml(i18n.t("Search applications by name or client ID"))}" data-search-api-label="${escapeHtml(i18n.t("Search APIs by name or resource URI"))}" data-search-scope-label="${escapeHtml(i18n.t("Search scopes"))}" data-no-matches-label="${escapeHtml(i18n.t("No matches found."))}" data-matches-label="${escapeHtml(i18n.t("{count} matches"))}" data-limited-matches-label="${escapeHtml(i18n.t("Showing first {shown} of {count} matches"))}"><div class="permission-rule-editor__list" data-permission-rule-list></div><button class="btn btn--ghost btn--sm btn--auto" type="button" data-permission-rule-add>${escapeHtml(i18n.t("Add rule"))}</button><details class="permission-rule-editor__advanced"><summary>${escapeHtml(i18n.t("Advanced JSON"))}</summary><label class="field field--wide"><span class="field__label">${escapeHtml(i18n.t("Rule document (JSON)"))}</span><textarea class="input mono" name="rules_json" rows="24" required data-permission-rule-json>${escapeHtml(rulesJson)}</textarea><p class="form-hint">${escapeHtml(i18n.t('Each rule has effect "allow" or "deny" and a condition. Conditions use "and"/"or" groups; leaves use =, !=, IN, or NOT IN for application, api, or scope. Empty rules deny everything.'))}</p></label><button class="btn btn--ghost btn--tiny btn--auto" type="button" data-permission-rule-apply-json>${escapeHtml(i18n.t("Apply JSON"))}</button></details></div><p class="form-hint field--wide">${escapeHtml(i18n.t("openid, profile, email, and offline_access follow base application/API access and cannot appear in scope rules."))}</p><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save rules"))}</button></div></form></div></section>`
  } else {
    const universalMembership = group.name === "all"
    const members = data.members ?? []
    const requests = data.membershipRequests ?? []
    const candidates = data.memberCandidates ?? []
    const query = data.memberQuery ?? ""
    const memberRows = members.map((member) => [
      `<a href="/console/users/${encodeURIComponent(member.userId)}?view=access"><b>${escapeHtml(member.name ?? member.alias)}</b><small class="form-hint">@${escapeHtml(member.alias)}</small></a>`,
      escapeHtml(member.email),
      statusBadge(i18n, !member.disabled, "Active", "Disabled"),
      `<span class="mono">${escapeHtml(fmtDateTime(i18n, member.joinedAt))}</span>`,
      universalMembership
        ? `<span class="form-hint">${escapeHtml(i18n.t("Protected"))}</span>`
        : `<form method="post" action="/console/groups/${id}/members/${encodeURIComponent(member.userId)}/remove">${csrfField(csrfToken)}<button class="btn btn--danger btn--tiny" type="submit">${escapeHtml(i18n.t("Remove"))}</button></form>`,
    ])
    const requestRows = requests.map((request) => [
      `<a href="/console/users/${encodeURIComponent(request.userId)}?view=access"><b>${escapeHtml(request.name ?? request.alias)}</b><small class="form-hint">@${escapeHtml(request.alias)}</small></a>`,
      escapeHtml(request.email),
      `<span class="mono">${escapeHtml(fmtDateTime(i18n, request.requestedAt))}</span>`,
      `<div class="actions"><form method="post" action="/console/groups/${id}/requests/${encodeURIComponent(request.userId)}/approve">${csrfField(csrfToken)}<button class="btn btn--primary btn--tiny" type="submit"${request.disabled ? " disabled" : ""}>${escapeHtml(i18n.t("Approve"))}</button></form><form method="post" action="/console/groups/${id}/requests/${encodeURIComponent(request.userId)}/reject">${csrfField(csrfToken)}<button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Reject"))}</button></form></div>`,
    ])
    const candidateRows = candidates.map((candidate) => [
      `<a href="/console/users/${encodeURIComponent(candidate.userId)}"><b>${escapeHtml(candidate.name ?? candidate.alias)}</b><small class="form-hint">@${escapeHtml(candidate.alias)}</small></a>`,
      escapeHtml(candidate.email),
      statusBadge(i18n, !candidate.disabled, "Active", "Disabled"),
      `<form method="post" action="/console/groups/${id}/members">${csrfField(csrfToken)}<input type="hidden" name="user_id" value="${escapeHtml(candidate.userId)}"><button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Add member"))}</button></form>`,
    ])
    const clear =
      query === ""
        ? ""
        : `<a class="btn btn--ghost btn--tiny" href="/console/groups/${id}?view=members">${escapeHtml(i18n.t("Clear"))}</a>`
    const search = `<form method="get" action="/console/groups/${id}" class="actions actions--start"><input type="hidden" name="view" value="members"><label class="field"><span class="field__label">${escapeHtml(i18n.t("Search users to add"))}</span><input class="input input--compact" type="search" name="q" value="${escapeHtml(query)}" maxlength="120" placeholder="${escapeHtml(i18n.t("Email, username, display name, or user ID"))}"></label><button class="btn btn--ghost btn--tiny" type="submit">${escapeHtml(i18n.t("Search"))}</button>${clear}</form>`
    const memberLimit = data.memberLimit ?? 50
    const memberOffset = data.memberOffset ?? 0
    const memberBase = `/console/groups/${id}?view=members${query === "" ? "" : `&q=${encodeURIComponent(query)}`}`
    const requestPanel =
      requests.length === 0
        ? ""
        : `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Pending requests"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Approve a request to add the user immediately, or reject it without changing membership."))}</p></div><span class="badge badge--warn">${escapeHtml(String(requests.length))}</span></div>${dataTable(i18n, ["User", "Email", "Requested", ""], requestRows, "No pending requests.")}</section>`
    const addPeoplePanel = universalMembership
      ? ""
      : `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Add people"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Search for an account, or choose from recently created recommendations."))}</p></div></div><div class="panel__body">${search}</div>${dataTable(i18n, ["User", "Email", "Status", ""], candidateRows, query === "" ? "No more people are available to add." : "No users match this search.")}</section>`
    panel = `${requestPanel}<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Members"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("People whose authorization includes this group's rules."))}</p></div><span class="badge">${escapeHtml(i18n.t(group.memberCount === 1 ? "{count} member" : "{count} members", { count: group.memberCount }))}</span></div>${dataTable(i18n, ["User", "Email", "Status", "Joined", ""], memberRows, "This group has no members.")}<div class="panel__body">${pager(i18n, memberBase, memberLimit, memberOffset, members.length, data.memberHasNext === true)}</div></section>${addPeoplePanel}`
  }
  return consoleShell(group.name, chrome, `${summary}${panel}`)
}

export function renderGroupDeleteConfirmation(
  chrome: ConsoleChrome,
  group: GroupSummary,
  csrfToken: string,
  error?: string,
): string {
  const { i18n } = chrome
  const id = encodeURIComponent(group.id)
  const memberSummary = i18n.t(
    group.memberCount === 1
      ? "{group} currently has {count} member."
      : "{group} currently has {count} members.",
    { group: group.name, count: group.memberCount },
  )
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Delete permission group?"))}</h2><p class="panel__desc">${escapeHtml(memberSummary)}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups/${id}?view=settings">${escapeHtml(i18n.t("Back to group"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Confirm group deletion"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("This permanently removes the group, every membership, and every permission rule. User accounts are not deleted."))}</p></div></div><div class="panel__body">${errorSummary(i18n, error)}<form method="post" action="/console/groups/${id}/delete" class="form-grid form-grid--single">${csrfField(csrfToken)}${textField(i18n, i18n.t("Type {value} to confirm", { value: group.name }), "confirmation", "", { required: true })}<div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Delete group"))}</button></div></form></div></section>`
  return consoleShell(i18n.t("Delete group?"), chrome, content)
}
