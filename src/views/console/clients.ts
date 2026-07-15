import type { ClientKind, ClientType, OAuthClient, OAuthResource } from "../../types/domain"
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
    <div><h2 class="panel__title">Applications</h2><p class="panel__desc">Interactive apps, devices, and services that trust this authorization server.</p></div>
    <a class="btn btn--primary btn--sm btn--auto" href="/console/clients/new">Create application</a>
  </div>
  <section class="panel">${dataTable(["Client ID", "Name", "Kind", "Status", ""], rows, "No clients yet.")}</section>`
  return consoleShell("Applications — Admin console", chrome, content)
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

function initialClientFormValues(
  client: OAuthClient | null,
  resources: readonly OAuthResource[] = [],
): ClientFormValues {
  const defaultScopes = ["openid", "profile", "email", "offline_access"]
  const suggestedResource = resources.find(
    (resource) =>
      resource.enabled && defaultScopes.every((scope) => resource.allowedScopes.includes(scope)),
  )
  return {
    clientId: client?.clientId ?? "",
    name: client?.name ?? "",
    type: client?.type ?? "public",
    clientKind: client?.clientKind ?? "application",
    redirectUris: (client?.redirectUris ?? []).join("\n"),
    postLogoutRedirectUris: (client?.postLogoutRedirectUris ?? []).join("\n"),
    allowedScopes: (client?.allowedScopes ?? defaultScopes).join("\n"),
    allowedGrantTypes: (client?.allowedGrantTypes ?? ["authorization_code", "refresh_token"]).join(
      "\n",
    ),
    allowedResources: (
      client?.allowedResources ??
      (suggestedResource === undefined ? [] : [suggestedResource.resourceUri])
    ).join("\n"),
    defaultResource: client?.defaultResource ?? suggestedResource?.resourceUri ?? "",
  }
}

function choiceCard(
  name: string,
  value: string,
  selected: string,
  title: string,
  description: string,
): string {
  return `<label class="choice-card"><input type="radio" name="${name}" value="${value}"${value === selected ? " checked" : ""} required><b>${escapeHtml(title)}</b><small>${escapeHtml(description)}</small></label>`
}

function resourceChoices(resources: readonly OAuthResource[], selected: string): string {
  const selectedResources = new Set(
    selected
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean),
  )
  const enabled = resources.filter((resource) => resource.enabled)
  if (enabled.length === 0) {
    return '<div class="wizard-empty">No enabled APIs are available. <a href="/console/resources/new">Create an API first</a>.</div>'
  }
  return `<div class="group-choice-grid resource-choice-grid">${enabled
    .map(
      (resource) => `<label class="group-choice resource-choice">
        <input type="checkbox" name="allowed_resources" value="${escapeHtml(resource.resourceUri)}" data-resource-scopes="${escapeHtml(resource.allowedScopes.join(" "))}"${selectedResources.has(resource.resourceUri) ? " checked" : ""}>
        <span><b>${escapeHtml(resource.name)}</b><small class="mono">${escapeHtml(resource.resourceUri)}</small><small>${escapeHtml(resource.allowedScopes.join(", "))}</small></span>
      </label>`,
    )
    .join("")}</div>`
}

function renderNewClientWizard(
  chrome: ConsoleChrome,
  csrfToken: string,
  resources: readonly OAuthResource[],
  feedback?: ClientFormFeedback,
): string {
  const values = feedback?.values ?? initialClientFormValues(null, resources)
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(feedback.error)}</div>`
  const stepNames = ["Application", "Login flow", "Access", "Review"]
  const markers = stepNames
    .map(
      (name, index) =>
        `<li class="wizard-step${index === 0 ? " wizard-step--active" : ""}" data-wizard-marker="${index}"><span>${index + 1}</span><strong>${escapeHtml(name)}</strong></li>`,
    )
    .join("")
  const reviewRow = (labelText: string, field: string, value: string) =>
    `<div class="wizard-review__row"><dt>${escapeHtml(labelText)}</dt><dd data-review-for="${field}">${escapeHtml(value || "—")}</dd></div>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">Create an application</h2><p class="panel__desc">A guided setup for the OAuth flow, redirect URLs, and API access.</p></div><a class="btn btn--ghost btn--sm" href="/console/clients">Cancel</a></div>
  <section class="panel">
    ${errorHtml === "" ? "" : `<div class="panel__body">${errorHtml}</div>`}
    <form method="post" action="/console/clients" data-console-wizard>
      ${csrfField(csrfToken)}
      <div class="wizard-shell">
        <aside class="wizard-rail"><h3>Application setup</h3><ol class="wizard-steps">${markers}</ol></aside>
        <div class="wizard-main">
          <fieldset class="wizard-panel wizard-panel--active" data-wizard-step="0"><legend>Tell us what you're building</legend><p class="wizard-panel__lead">These choices determine the safest OAuth flow. You can tune advanced settings after creation.</p><div class="wizard-grid">
            ${textField("Application name", "name", values.name, { required: true, placeholder: "Customer portal" })}
            ${textField("Client ID", "client_id", values.clientId, { required: true, placeholder: "customer_portal" })}
            <fieldset class="field-cluster field--wide"><legend>Application kind</legend><div class="choice-cards">
              ${choiceCard("client_kind", "application", values.clientKind, "Web application", "Interactive browser sign-in with authorization code and PKCE.")}
              ${choiceCard("client_kind", "device", values.clientKind, "Device or CLI", "Input-constrained devices using the OAuth device authorization grant.")}
              ${choiceCard("client_kind", "service", values.clientKind, "Machine to machine", "A backend service authenticating without a person.")}
            </div></fieldset>
            <fieldset class="field-cluster field--wide"><legend>Client authentication</legend><div class="choice-cards choice-cards--two">
              ${choiceCard("type", "public", values.type, "Public", "No stored secret. Best for browser, mobile, desktop, and CLI clients.")}
              ${choiceCard("type", "confidential", values.type, "Confidential", "Receives a one-time client secret for a trusted backend.")}
            </div></fieldset>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="1"><legend>Configure the login flow</legend><p class="wizard-panel__lead">Callback URLs must match exactly. Local loopback HTTP is allowed for development.</p><div class="wizard-grid">
            <div class="field--wide">${textAreaField("Redirect URIs", "redirect_uris", values.redirectUris, "One exact callback URL per line.", { required: values.clientKind === "application" })}</div>
            <div class="field--wide">${textAreaField("Post-logout redirect URIs", "post_logout_redirect_uris", values.postLogoutRedirectUris, "Where users may return after RP-Initiated Logout.")}</div>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="2"><legend>Choose access</legend><p class="wizard-panel__lead">Grant only the scopes and API audiences this application needs.</p><div class="wizard-grid">
            <div>${textAreaField("Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line, such as openid, profile, or api.read.", { required: true })}</div>
            <div>${textAreaField("Allowed grant types", "allowed_grant_types", values.allowedGrantTypes, GRANT_HINT, { required: true })}</div>
            <fieldset class="field-cluster field--wide"><legend>APIs</legend>${resourceChoices(resources, values.allowedResources)}<p class="form-hint">Choose at least one enabled API. The wizard suggests one whose scopes match the selected application kind.</p></fieldset>
            <div class="field--wide">${textField("Default resource", "default_resource", values.defaultResource, { placeholder: "https://api.example.com" })}</div>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="3"><legend>Review and create</legend><p class="wizard-panel__lead">Check the important values before registering the application. Authorization-code clients always use S256 PKCE.</p><dl class="wizard-review">
            ${reviewRow("Name", "name", values.name)}${reviewRow("Client ID", "client_id", values.clientId)}${reviewRow("Kind", "client_kind", label(values.clientKind))}${reviewRow("Authentication", "type", label(values.type))}${reviewRow("Redirect URIs", "redirect_uris", values.redirectUris)}${reviewRow("Scopes", "allowed_scopes", values.allowedScopes)}${reviewRow("Grant types", "allowed_grant_types", values.allowedGrantTypes)}${reviewRow("Resources", "allowed_resources", values.allowedResources)}
          </dl></fieldset>
          <div class="wizard-actions"><button class="btn btn--ghost btn--auto" type="button" data-wizard-back hidden>Back</button><div class="wizard-actions__right"><button class="btn btn--primary btn--auto" type="button" data-wizard-next>Continue</button><button class="btn btn--primary btn--auto" type="submit" data-wizard-submit hidden>Create application</button></div></div>
        </div>
      </div>
    </form>
  </section>`
  return consoleShell("New application — Admin console", chrome, content)
}

export function renderClientForm(
  chrome: ConsoleChrome,
  client: OAuthClient | null,
  csrfToken: string,
  feedback?: ClientFormFeedback,
  resources: readonly OAuthResource[] = [],
): string {
  if (client === null) {
    return renderNewClientWizard(chrome, csrfToken, resources, feedback)
  }
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
    <a class="btn btn--ghost btn--sm" href="/console/clients">Back to applications</a>
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
