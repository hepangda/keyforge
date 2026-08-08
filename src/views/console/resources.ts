import type { OAuthResource } from "../../types/domain"
import { escapeHtml } from "../layout"
import {
  checkboxField,
  csrfField,
  dataTable,
  scopeTags,
  statusBadge,
  textAreaField,
  textField,
} from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

export function renderResourcesList(
  chrome: ConsoleChrome,
  resources: readonly OAuthResource[],
): string {
  const { i18n } = chrome
  const rows = resources.map((resource) => [
    `<span class="mono">${escapeHtml(resource.resourceUri)}</span>`,
    `<b>${escapeHtml(resource.name)}</b>`,
    scopeTags(resource.allowedScopes),
    statusBadge(i18n, resource.enabled, "Enabled", "Disabled"),
    `<div class="actions"><a class="btn btn--ghost btn--tiny" href="/console/resources/${encodeURIComponent(resource.resourceUri)}">${escapeHtml(i18n.t("Edit"))}</a></div>`,
  ])
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("APIs"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Protected APIs and audiences that tokens can be issued for."))}</p></div><a class="btn btn--primary btn--sm btn--auto" href="/console/resources/new">${escapeHtml(i18n.t("Create API"))}</a></div><section class="panel">${dataTable(i18n, ["Resource URI", "Name", "Scopes", "Status", ""], rows, "No APIs yet.")}</section>`
  return consoleShell(i18n.t("APIs"), chrome, content)
}

export type ResourceFormValues = {
  readonly resourceUri: string
  readonly name: string
  readonly allowedScopes: string
  readonly enabled: boolean
}

export type ResourceFormFeedback = {
  readonly values: ResourceFormValues
  readonly field: "resource_uri" | "name" | "allowed_scopes" | null
  readonly error: string
}

export function renderResourceForm(
  chrome: ConsoleChrome,
  resource: OAuthResource | null,
  csrfToken: string,
  returnTo = "/",
  feedback?: ResourceFormFeedback,
): string {
  const { i18n } = chrome
  const isNew = resource === null
  const values = feedback?.values ?? {
    resourceUri: resource?.resourceUri ?? "",
    name: resource?.name ?? "",
    allowedScopes: (resource?.allowedScopes ?? []).join("\n"),
    enabled: resource?.enabled ?? true,
  }
  const action = isNew
    ? "/console/resources"
    : `/console/resources/${encodeURIComponent(resource.resourceUri)}`
  const fieldError = (field: ResourceFormFeedback["field"]) =>
    feedback?.field === field ? feedback.error : undefined
  const identity = isNew
    ? textField(i18n, "Resource URI", "resource_uri", values.resourceUri, {
        required: true,
        placeholder: "https://api.pangda.app",
        error: fieldError("resource_uri"),
      })
    : `${textField(i18n, "Resource URI", "resource_uri_display", resource.resourceUri, { readonly: true })}${checkboxField(i18n, "Enabled", "enabled", values.enabled)}`
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
  const deleteAction = isNew
    ? ""
    : `<a class="btn btn--danger btn--auto" href="/console/resources/${encodeURIComponent(resource.resourceUri)}/delete">${escapeHtml(i18n.t("Delete API"))}</a>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t(isNew ? "Create API" : resource.name))}</h2><p class="panel__desc">${escapeHtml(i18n.t(isNew ? "Register a protected API." : "Edit API configuration."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/resources">${escapeHtml(i18n.t("Back to APIs"))}</a></div><section class="panel"><div class="panel__body">${errorHtml}<form method="post" action="${action}" class="form-grid">${csrfField(csrfToken)}<input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">${identity}${textField(i18n, "Display name", "name", values.name, { required: true, error: fieldError("name") })}<div class="field--wide">${textAreaField(i18n, "Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line.", { error: fieldError("allowed_scopes") })}</div><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t(isNew ? "Create API" : "Save changes"))}</button>${deleteAction}</div></form></div></section>`
  const auditLink = isNew
    ? ""
    : `<div class="actions actions--start"><a class="btn btn--ghost btn--auto" href="/console/audit?resource_uri=${encodeURIComponent(resource.resourceUri)}">${escapeHtml(i18n.t("View audit events"))}</a></div>`
  return consoleShell(
    isNew ? i18n.t("Create API") : resource.name,
    chrome,
    `${content}${auditLink}`,
  )
}

export function renderResourceDeleteConfirmation(
  chrome: ConsoleChrome,
  resource: OAuthResource,
  csrfToken: string,
  error?: string,
): string {
  const { i18n } = chrome
  const id = encodeURIComponent(resource.resourceUri)
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(error))}</div>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Delete API?"))}</h2><p class="panel__desc">${escapeHtml(resource.name)}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/resources/${id}">${escapeHtml(i18n.t("Back to API"))}</a></div><section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Confirm API deletion"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("This removes the API registration, permission-group assignments, client references, and stored authorizations. Existing access tokens remain valid until they expire."))}</p></div></div><div class="panel__body">${errorHtml}<form method="post" action="/console/resources/${id}/delete" class="form-grid form-grid--single">${csrfField(csrfToken)}${textField(i18n, i18n.t("Type {value} to confirm", { value: resource.resourceUri }), "confirmation", "", { required: true })}<div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Delete API"))}</button></div></form></div></section>`
  return consoleShell(i18n.t("Delete API?"), chrome, content)
}
