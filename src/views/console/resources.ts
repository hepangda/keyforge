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
  const rows = resources.map((resource) => [
    `<span class="mono">${escapeHtml(resource.resourceUri)}</span>`,
    `<b>${escapeHtml(resource.name)}</b>`,
    scopeTags(resource.allowedScopes),
    statusBadge(resource.enabled, "Enabled", "Disabled"),
    `<div class="actions"><a class="btn btn--ghost btn--tiny" href="/console/resources/${encodeURIComponent(resource.resourceUri)}">Edit</a></div>`,
  ])
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">Resources</h2><p class="panel__desc">Protected APIs (audiences) that tokens can be issued for.</p></div>
    <a class="btn btn--primary btn--sm btn--auto" href="/console/resources/new">New resource</a>
  </div>
  <section class="panel">${dataTable(["Resource URI", "Name", "Scopes", "Status", ""], rows, "No resources yet.")}</section>`
  return consoleShell("Resources — Admin console", chrome, content)
}

export function renderResourceForm(
  chrome: ConsoleChrome,
  resource: OAuthResource | null,
  csrfToken: string,
): string {
  const isNew = resource === null
  const action = isNew
    ? "/console/resources"
    : `/console/resources/${encodeURIComponent(resource.resourceUri)}`
  const identity = isNew
    ? textField("Resource URI", "resource_uri", "", {
        required: true,
        placeholder: "https://api.pangda.app",
      })
    : `${textField("Resource URI", "resource_uri_display", resource.resourceUri, { readonly: true })}${checkboxField("Enabled", "enabled", resource.enabled)}`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${isNew ? "New resource" : escapeHtml(resource.name)}</h2><p class="panel__desc">${isNew ? "Register a protected API." : "Edit resource configuration."}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/resources">Back to resources</a>
  </div>
  <section class="panel"><div class="panel__body">
    <form method="post" action="${action}" class="form-grid">
      ${csrfField(csrfToken)}
      ${identity}
      ${textField("Display name", "name", resource?.name ?? "", { required: true })}
      ${textAreaField("Allowed scopes", "allowed_scopes", (resource?.allowedScopes ?? []).join("\n"), "One scope per line.")}
      <div><button class="btn btn--primary btn--auto" type="submit">${isNew ? "Create resource" : "Save changes"}</button></div>
    </form>
  </div></section>`
  return consoleShell(
    isNew ? "New resource — Admin console" : `${resource.name} — Admin console`,
    chrome,
    content,
  )
}
