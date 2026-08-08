import type {
  GroupMemberCandidate,
  GroupMemberSummary,
  GroupMembershipRequestSummary,
} from "../../db/queries/group-memberships"
import type { GroupSummary } from "../../db/queries/users"
import type { I18n } from "../../i18n"
import type { OAuthClient, OAuthResource } from "../../types/domain"
import { escapeHtml } from "../layout"
import { searchPicker } from "../search-picker"
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

export type GroupFormValues = { readonly name: string; readonly description: string }

export type GroupFormFeedback = {
  readonly values: GroupFormValues
  readonly field: "name" | "description" | null
  readonly error: string
}

export type GroupDetailView = "settings" | "access" | "members"

export type GroupDetailData = {
  readonly group: GroupSummary
  readonly view: GroupDetailView
  readonly csrfToken: string
  readonly clients?: readonly OAuthClient[]
  readonly resources?: readonly OAuthResource[]
  readonly selectedClientIds?: ReadonlySet<string>
  readonly selectedResourceUris?: ReadonlySet<string>
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

function clientChoices(
  i18n: I18n,
  clients: readonly OAuthClient[],
  selectedIds: ReadonlySet<string>,
): string {
  if (clients.length === 0) {
    return `<div class="wizard-empty">${escapeHtml(i18n.t("No user applications or devices are registered."))} <a href="/console/clients/new">${escapeHtml(i18n.t("Create an application first"))}</a>.</div>`
  }
  return searchPicker(
    i18n,
    {
      id: "group-client-access",
      name: "client_ids",
      label: "Applications and devices",
      placeholder: "Search applications by name or client ID",
      emptySelection: "No applications or devices selected.",
      maxSelections: 100,
    },
    clients.map((client, index) => ({
      value: client.clientId,
      title: client.name,
      detail: `${i18n.t(client.clientKind === "device" ? "Device" : "Application")}${client.enabled ? "" : ` · ${i18n.t("Disabled")}`}`,
      meta: client.clientId,
      selected: selectedIds.has(client.clientId),
      recommended: client.enabled && index < 6,
    })),
  )
}

function resourceChoices(
  i18n: I18n,
  resources: readonly OAuthResource[],
  selectedUris: ReadonlySet<string>,
): string {
  if (resources.length === 0) {
    return `<div class="wizard-empty">${escapeHtml(i18n.t("No APIs are registered."))} <a href="/console/resources/new">${escapeHtml(i18n.t("Create an API first"))}</a>.</div>`
  }
  return searchPicker(
    i18n,
    {
      id: "group-resource-access",
      name: "resource_uris",
      label: "APIs",
      placeholder: "Search APIs by name or resource URI",
      emptySelection: "No APIs selected.",
      maxSelections: 100,
    },
    resources.map((resource, index) => ({
      value: resource.resourceUri,
      title: resource.name,
      detail: resource.enabled ? i18n.t("Enabled") : i18n.t("Disabled"),
      meta: resource.resourceUri,
      selected: selectedUris.has(resource.resourceUri),
      recommended: resource.enabled && index < 6,
    })),
  )
}

export function renderGroupsList(chrome: ConsoleChrome, groups: readonly GroupSummary[]): string {
  const { i18n } = chrome
  const rows = groups.map((group) => {
    const protectedGroup = group.name === "admins" || group.name === "all"
    const href = `/console/groups/${encodeURIComponent(group.id)}${protectedGroup ? "?view=access" : ""}`
    return [
      `<span class="tag">${escapeHtml(group.name)}</span>`,
      escapeHtml(group.description ?? i18n.t("No description")),
      String(group.memberCount),
      `<div class="actions">${protectedGroup ? `<span class="form-hint">${escapeHtml(i18n.t("Protected"))}</span>` : ""}<a class="btn btn--ghost btn--tiny" href="${href}">${escapeHtml(i18n.t("Manage"))}</a></div>`,
    ]
  })
  const emptyAction =
    groups.length === 0
      ? `<div class="panel__body"><a class="btn btn--primary btn--auto" href="/console/groups/new">${escapeHtml(i18n.t("Create a group"))}</a></div>`
      : ""
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Permission groups"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Assign memberships and control which applications and APIs each group can access."))}</p></div><a class="btn btn--primary btn--sm" href="/console/groups/new">${escapeHtml(i18n.t("Create a group"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Permission groups"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Members can receive user tokens only for applications and APIs assigned to this permission group."))}</p></div></div>${dataTable(i18n, ["Group", "Description", "Members", ""], rows, "No groups found. Create the first group to begin.")}${emptyAction}</section>`
  return consoleShell(i18n.t("Permission groups"), chrome, content)
}

export function renderGroupCreateForm(
  chrome: ConsoleChrome,
  csrfToken: string,
  feedback?: GroupFormFeedback,
): string {
  const { i18n } = chrome
  const values = feedback?.values ?? { name: "", description: "" }
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Create a group"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Members can receive user tokens only for applications and APIs assigned to this permission group."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups">${escapeHtml(i18n.t("Back to groups"))}</a></div><section class="panel"><div class="panel__body">${errorSummary(i18n, feedback?.error)}<form method="post" action="/console/groups" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Group name", "name", values.name, { required: true, placeholder: "support-agents", error: feedback?.field === "name" ? feedback.error : undefined })}${textField(i18n, "Description", "description", values.description, { placeholder: "What membership grants", error: feedback?.field === "description" ? feedback.error : undefined })}<div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Create group"))}</button></div></form></div></section>`
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
  const summary = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(group.name)}</h2><p class="panel__desc">${escapeHtml(i18n.t("Members can receive user tokens only for applications and APIs assigned to this permission group."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups">${escapeHtml(i18n.t("Back to groups"))}</a></div>${tabs}`
  let panel: string
  if (view === "settings") {
    const values = data.settingsFeedback?.values ?? {
      name: group.name,
      description: group.description ?? "",
    }
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Settings"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Name and description for this permission group."))}</p></div></div><div class="panel__body">${errorSummary(i18n, data.settingsFeedback?.error)}<form method="post" action="/console/groups/${id}/settings" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Group name", "name", values.name, { required: true, placeholder: "support-agents", error: data.settingsFeedback?.field === "name" ? data.settingsFeedback.error : undefined })}${textField(i18n, "Description", "description", values.description, { placeholder: "What membership grants", error: data.settingsFeedback?.field === "description" ? data.settingsFeedback.error : undefined })}<div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button><a class="btn btn--danger btn--auto" href="/console/groups/${id}/delete">${escapeHtml(i18n.t("Delete group"))}</a></div></form></div></section>`
  } else if (view === "access") {
    const selectedClientIds = data.selectedClientIds ?? new Set<string>()
    const selectedResourceUris = data.selectedResourceUris ?? new Set<string>()
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Access"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Members can receive user tokens only for applications and APIs assigned to this permission group."))}</p></div></div><div class="panel__body">${errorSummary(i18n, data.accessError)}<form method="post" action="/console/groups/${id}/access" class="form-grid">${csrfField(csrfToken)}<fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Applications and devices"))}</legend>${clientChoices(i18n, data.clients ?? [], selectedClientIds)}</fieldset><fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("APIs"))}</legend>${resourceChoices(i18n, data.resources ?? [], selectedResourceUris)}</fieldset><p class="form-hint field--wide">${escapeHtml(i18n.t("No access is granted until at least one application and one API are selected."))}</p><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button></div></form></div></section>`
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
    panel = `${requestPanel}<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Members"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("People who currently receive this group's application and API access."))}</p></div><span class="badge">${escapeHtml(i18n.t(group.memberCount === 1 ? "{count} member" : "{count} members", { count: group.memberCount }))}</span></div>${dataTable(i18n, ["User", "Email", "Status", "Joined", ""], memberRows, "This group has no members.")}<div class="panel__body">${pager(i18n, memberBase, memberLimit, memberOffset, members.length, data.memberHasNext === true)}</div></section>${addPeoplePanel}`
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
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Delete permission group?"))}</h2><p class="panel__desc">${escapeHtml(memberSummary)}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups/${id}?view=settings">${escapeHtml(i18n.t("Back to group"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Confirm group deletion"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("This permanently removes the group, every membership, and every application or API assignment. User accounts are not deleted."))}</p></div></div><div class="panel__body">${errorSummary(i18n, error)}<form method="post" action="/console/groups/${id}/delete" class="form-grid form-grid--single">${csrfField(csrfToken)}${textField(i18n, i18n.t("Type {value} to confirm", { value: group.name }), "confirmation", "", { required: true })}<div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Delete group"))}</button></div></form></div></section>`
  return consoleShell(i18n.t("Delete group?"), chrome, content)
}
