import type { GroupSummary } from "../../db/queries/users"
import type { I18n } from "../../i18n"
import type { OAuthClient, OAuthResource } from "../../types/domain"
import { escapeHtml } from "../layout"
import { csrfField, dataTable, secondaryTabs, statusBadge, textField } from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

export type GroupFormValues = { readonly name: string; readonly description: string }

export type GroupFormFeedback = {
  readonly values: GroupFormValues
  readonly field: "name" | "description" | null
  readonly error: string
}

export type GroupDetailView = "settings" | "access"

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
  return `<div class="group-choice-grid">${clients
    .map(
      (client) => `<label class="group-choice">
        <input type="checkbox" name="client_ids" value="${escapeHtml(client.clientId)}"${selectedIds.has(client.clientId) ? " checked" : ""}>
        <span><b>${escapeHtml(client.name)}${client.enabled ? "" : ` ${statusBadge(i18n, false, "Enabled", "Disabled")}`}</b><small class="mono">${escapeHtml(client.clientId)}</small><small>${escapeHtml(i18n.t(client.clientKind === "device" ? "Device" : "Application"))}</small></span>
      </label>`,
    )
    .join("")}</div>`
}

function resourceChoices(
  i18n: I18n,
  resources: readonly OAuthResource[],
  selectedUris: ReadonlySet<string>,
): string {
  if (resources.length === 0) {
    return `<div class="wizard-empty">${escapeHtml(i18n.t("No APIs are registered."))} <a href="/console/resources/new">${escapeHtml(i18n.t("Create an API first"))}</a>.</div>`
  }
  return `<div class="group-choice-grid">${resources
    .map(
      (resource) => `<label class="group-choice">
        <input type="checkbox" name="resource_uris" value="${escapeHtml(resource.resourceUri)}"${selectedUris.has(resource.resourceUri) ? " checked" : ""}>
        <span><b>${escapeHtml(resource.name)}${resource.enabled ? "" : ` ${statusBadge(i18n, false, "Enabled", "Disabled")}`}</b><small class="mono">${escapeHtml(resource.resourceUri)}</small></span>
      </label>`,
    )
    .join("")}</div>`
}

export function renderGroupsList(chrome: ConsoleChrome, groups: readonly GroupSummary[]): string {
  const { i18n } = chrome
  const rows = groups.map((group) => {
    const href = `/console/groups/${encodeURIComponent(group.id)}${group.name === "admins" ? "?view=access" : ""}`
    return [
      `<span class="tag">${escapeHtml(group.name)}</span>`,
      escapeHtml(group.description ?? i18n.t("No description")),
      String(group.memberCount),
      `<div class="actions">${group.name === "admins" ? `<span class="form-hint">${escapeHtml(i18n.t("Protected"))}</span>` : ""}<a class="btn btn--ghost btn--tiny" href="${href}">${escapeHtml(i18n.t("Manage"))}</a></div>`,
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
  ])
  const summary = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(group.name)}</h2><p class="panel__desc">${escapeHtml(i18n.t("Members can receive user tokens only for applications and APIs assigned to this permission group."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/groups">${escapeHtml(i18n.t("Back to groups"))}</a></div>${tabs}`
  let panel: string
  if (view === "settings") {
    const values = data.settingsFeedback?.values ?? {
      name: group.name,
      description: group.description ?? "",
    }
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Settings"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Name and description for this permission group."))}</p></div></div><div class="panel__body">${errorSummary(i18n, data.settingsFeedback?.error)}<form method="post" action="/console/groups/${id}/settings" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Group name", "name", values.name, { required: true, placeholder: "support-agents", error: data.settingsFeedback?.field === "name" ? data.settingsFeedback.error : undefined })}${textField(i18n, "Description", "description", values.description, { placeholder: "What membership grants", error: data.settingsFeedback?.field === "description" ? data.settingsFeedback.error : undefined })}<div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button><a class="btn btn--danger btn--auto" href="/console/groups/${id}/delete">${escapeHtml(i18n.t("Delete group"))}</a></div></form></div></section>`
  } else {
    const selectedClientIds = data.selectedClientIds ?? new Set<string>()
    const selectedResourceUris = data.selectedResourceUris ?? new Set<string>()
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Access"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Members can receive user tokens only for applications and APIs assigned to this permission group."))}</p></div></div><div class="panel__body">${errorSummary(i18n, data.accessError)}<form method="post" action="/console/groups/${id}/access" class="form-grid">${csrfField(csrfToken)}<fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Applications and devices"))}</legend>${clientChoices(i18n, data.clients ?? [], selectedClientIds)}</fieldset><fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("APIs"))}</legend>${resourceChoices(i18n, data.resources ?? [], selectedResourceUris)}</fieldset><p class="form-hint field--wide">${escapeHtml(i18n.t("No access is granted until at least one application and one API are selected."))}</p><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button></div></form></div></section>`
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
