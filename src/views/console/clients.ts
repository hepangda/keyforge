import type { ClientKind, ClientType, OAuthClient } from "../../types/domain"
import { escapeHtml } from "../layout"
import {
  csrfField,
  dataTable,
  selectField,
  statusBadge,
  textAreaField,
  textField,
} from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

const TYPE_LABELS: Readonly<Record<string, string>> = {
  public: "Public",
  confidential: "Confidential",
  application: "Application",
  device: "Device",
  service: "Service",
}

function label(value: string): string {
  return TYPE_LABELS[value] ?? value
}

export function renderClientsList(chrome: ConsoleChrome, clients: readonly OAuthClient[]): string {
  const rows = clients.map((client) => [
    `<span class="mono">${escapeHtml(client.clientId)}</span>`,
    `<b>${escapeHtml(client.name)}</b>`,
    `${escapeHtml(label(client.type))} · ${escapeHtml(label(client.clientKind))}`,
    statusBadge(client.enabled, "Enabled", "Disabled"),
    `<div class="actions"><a class="btn btn--ghost btn--tiny" href="/console/clients/${escapeHtml(client.clientId)}">Edit</a></div>`,
  ])
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">OAuth clients</h2><p class="panel__desc">Applications, devices, and services that use this server.</p></div>
    <a class="btn btn--primary btn--sm btn--auto" href="/console/clients/new">New client</a>
  </div>
  <section class="panel">${dataTable(["Client ID", "Name", "Kind", "Status", ""], rows, "No clients yet.")}</section>`
  return consoleShell("Clients — Admin console", chrome, content)
}

const GRANT_HINT =
  "One per line. e.g. authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:device_code"

export type ClientFormValues = {
  readonly clientId: string
  readonly name: string
  readonly type: ClientType
  readonly clientKind: ClientKind
  readonly redirectUris: string
  readonly postLogoutRedirectUris: string
  readonly allowedScopes: string
  readonly allowedGrantTypes: string
  readonly allowedResources: string
  readonly defaultResource: string
}

export type ClientFormFeedback = {
  readonly values: ClientFormValues
  readonly error: string
}

function initialClientFormValues(client: OAuthClient | null): ClientFormValues {
  return {
    clientId: client?.clientId ?? "",
    name: client?.name ?? "",
    type: client?.type ?? "public",
    clientKind: client?.clientKind ?? "application",
    redirectUris: (client?.redirectUris ?? []).join("\n"),
    postLogoutRedirectUris: (client?.postLogoutRedirectUris ?? []).join("\n"),
    allowedScopes: (client?.allowedScopes ?? []).join("\n"),
    allowedGrantTypes: (client?.allowedGrantTypes ?? []).join("\n"),
    allowedResources: (client?.allowedResources ?? []).join("\n"),
    defaultResource: client?.defaultResource ?? "",
  }
}

export function renderClientForm(
  chrome: ConsoleChrome,
  client: OAuthClient | null,
  csrfToken: string,
  feedback?: ClientFormFeedback,
): string {
  const isNew = client === null
  const values = feedback?.values ?? initialClientFormValues(client)
  const action = isNew ? "/console/clients" : `/console/clients/${escapeHtml(client.clientId)}`
  const identity = isNew
    ? `${textField("Client ID", "client_id", values.clientId, { required: true, placeholder: "my_app" })}
       ${selectField(
         "Type",
         "type",
         [
           { value: "public", label: "Public" },
           { value: "confidential", label: "Confidential (gets a secret)" },
         ],
         values.type,
       )}
       ${selectField(
         "Kind",
         "client_kind",
         [
           { value: "application", label: "Application" },
           { value: "device", label: "Device" },
           { value: "service", label: "Service" },
         ],
         values.clientKind,
       )}`
    : `${textField("Client ID", "client_id_display", client.clientId, { readonly: true })}
       <p class="form-hint">Type: ${escapeHtml(label(client.type))} · Kind: ${escapeHtml(label(client.clientKind))} · Secret: ${client.clientSecretHash === null ? "none" : "set"}</p>`
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(feedback.error)}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${isNew ? "New client" : escapeHtml(client.name)}</h2><p class="panel__desc">${isNew ? "Register an OAuth client." : "Edit client configuration."}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/clients">Back to clients</a>
  </div>
  <section class="panel"><div class="panel__body">
    ${errorHtml}
    <form method="post" action="${action}" class="form-grid">
      ${csrfField(csrfToken)}
      ${identity}
      ${textField("Display name", "name", values.name, { required: true })}
      ${textAreaField("Redirect URIs", "redirect_uris", values.redirectUris, "One URL per line.")}
      ${textAreaField("Post-logout redirect URIs", "post_logout_redirect_uris", values.postLogoutRedirectUris, "Exact RP-Initiated Logout destinations, one per line.")}
      ${textAreaField("Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line.")}
      ${textAreaField("Allowed grant types", "allowed_grant_types", values.allowedGrantTypes, GRANT_HINT)}
      ${textAreaField("Allowed resources", "allowed_resources", values.allowedResources, "Resource URIs, one per line.")}
      ${textField("Default resource", "default_resource", values.defaultResource)}
      <p class="form-hint">Authorization-code clients always require PKCE with S256.</p>
      <div><button class="btn btn--primary btn--auto" type="submit">${isNew ? "Create client" : "Save changes"}</button></div>
    </form>
  </div></section>
  ${isNew ? "" : renderClientDangerZone(client, csrfToken)}`
  return consoleShell(
    isNew ? "New client — Admin console" : `${client.name} — Admin console`,
    chrome,
    content,
  )
}

function renderClientDangerZone(client: OAuthClient, csrfToken: string): string {
  const id = escapeHtml(client.clientId)
  const toggle = client.enabled
    ? `<form method="post" action="/console/clients/${id}/disable">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit">Disable</button></form>`
    : `<form method="post" action="/console/clients/${id}/enable">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit">Enable</button></form>`
  const rotate =
    client.type === "confidential"
      ? `<a class="btn btn--ghost btn--auto" href="/console/clients/${id}/rotate-secret">Rotate secret</a>`
      : ""
  return `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Manage</h2><p class="panel__desc">Enable, disable, rotate the secret, or delete this client.</p></div></div>
    <div class="panel__body"><div class="actions actions--start">
      ${toggle}
      ${rotate}
      <a class="btn btn--danger btn--auto" href="/console/clients/${id}/delete">Delete client</a>
    </div></div>
  </section>`
}

export function renderClientActionConfirmation(
  chrome: ConsoleChrome,
  client: OAuthClient,
  csrfToken: string,
  action: "rotate-secret" | "delete",
  error?: string,
): string {
  const deleting = action === "delete"
  const id = escapeHtml(client.clientId)
  const title = deleting ? "Delete OAuth client?" : "Rotate client secret?"
  const consequence = deleting
    ? "This permanently removes the client, its grants, consents, and refresh tokens. Applications using it will stop working."
    : "The current secret stops working immediately. Update the application with the new secret before it makes another request."
  const button = deleting ? "Delete client" : "Rotate secret"
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(error)}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${title}</h2><p class="panel__desc">${escapeHtml(client.name)}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/clients/${id}">Cancel</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Confirm high-impact change</h2><p class="panel__desc">${consequence}</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/clients/${id}/${action}" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField(`Type ${client.clientId} to confirm`, "confirmation", "", { required: true })}
        <div><button class="btn btn--danger btn--auto" type="submit">${button}</button></div>
      </form>
    </div>
  </section>`
  return consoleShell(`${title} — Admin console`, chrome, content)
}

export function renderClientSecret(
  chrome: ConsoleChrome,
  clientId: string,
  secret: string,
): string {
  const content = `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Client secret</h2><p class="panel__desc">Copy this now — it is shown once and cannot be retrieved again.</p></div></div>
    <div class="panel__body">
      <p class="form-hint">Secret for <span class="mono">${escapeHtml(clientId)}</span></p>
      <div class="secret">${escapeHtml(secret)}</div>
      <p class="secret-done"><a class="btn btn--primary btn--sm btn--auto" href="/console/clients/${escapeHtml(clientId)}">Done</a></p>
    </div>
  </section>`
  return consoleShell("Client secret — Admin console", chrome, content)
}
