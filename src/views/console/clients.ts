import type { I18n } from "../../i18n"
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
  const { i18n } = chrome
  const rows = clients.map((client) => [
    `<span class="mono">${escapeHtml(client.clientId)}</span>`,
    `<b>${escapeHtml(client.name)}</b>`,
    `${escapeHtml(i18n.t(label(client.type)))} · ${escapeHtml(i18n.t(label(client.clientKind)))}`,
    statusBadge(i18n, client.enabled, "Enabled", "Disabled"),
    `<div class="actions"><a class="btn btn--ghost btn--tiny" href="/console/clients/${escapeHtml(client.clientId)}">${escapeHtml(i18n.t("Edit"))}</a></div>`,
  ])
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(i18n.t("Applications"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Interactive apps, devices, and services that trust this authorization server."))}</p></div>
    <a class="btn btn--primary btn--sm btn--auto" href="/console/clients/new">${escapeHtml(i18n.t("Create application"))}</a>
  </div>
  <section class="panel">${dataTable(i18n, ["Client ID", "Name", "Kind", "Status", ""], rows, "No clients yet.")}</section>`
  return consoleShell(i18n.t("Applications"), chrome, content)
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
  i18n: I18n,
  name: string,
  value: string,
  selected: string,
  title: string,
  description: string,
): string {
  return `<label class="choice-card"><input type="radio" name="${name}" value="${value}"${value === selected ? " checked" : ""} required><b>${escapeHtml(i18n.t(title))}</b><small>${escapeHtml(i18n.t(description))}</small></label>`
}

function resourceChoices(
  i18n: I18n,
  resources: readonly OAuthResource[],
  selected: string,
): string {
  const selectedResources = new Set(
    selected
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean),
  )
  const enabled = resources.filter((resource) => resource.enabled)
  if (enabled.length === 0) {
    return `<div class="wizard-empty">${escapeHtml(i18n.t("No enabled APIs are available."))} <a href="/console/resources/new">${escapeHtml(i18n.t("Create an API first"))}</a>.</div>`
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
  const { i18n } = chrome
  const values = feedback?.values ?? initialClientFormValues(null, resources)
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
  const stepNames = ["Application", "Login flow", "Access", "Review"]
  const markers = stepNames
    .map(
      (name, index) =>
        `<li class="wizard-step${index === 0 ? " wizard-step--active" : ""}" data-wizard-marker="${index}"><span>${index + 1}</span><strong>${escapeHtml(i18n.t(name))}</strong></li>`,
    )
    .join("")
  const reviewRow = (labelText: string, field: string, value: string) =>
    `<div class="wizard-review__row"><dt>${escapeHtml(i18n.t(labelText))}</dt><dd data-review-for="${field}">${escapeHtml(value || "—")}</dd></div>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Create an application"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("A guided setup for the OAuth flow, redirect URLs, and API access."))}</p></div><a class="btn btn--ghost btn--sm" href="/console/clients">${escapeHtml(i18n.t("Cancel"))}</a></div>
  <section class="panel">
    ${errorHtml === "" ? "" : `<div class="panel__body">${errorHtml}</div>`}
    <form method="post" action="/console/clients" data-console-wizard data-label-application="${escapeHtml(i18n.t("Web application"))}" data-label-device="${escapeHtml(i18n.t("Device or CLI"))}" data-label-service="${escapeHtml(i18n.t("Machine to machine"))}" data-label-public="${escapeHtml(i18n.t("Public"))}" data-label-confidential="${escapeHtml(i18n.t("Confidential"))}">
      ${csrfField(csrfToken)}
      <div class="wizard-shell">
        <aside class="wizard-rail"><h3>${escapeHtml(i18n.t("Application setup"))}</h3><ol class="wizard-steps">${markers}</ol></aside>
        <div class="wizard-main">
          <fieldset class="wizard-panel wizard-panel--active" data-wizard-step="0"><legend>${escapeHtml(i18n.t("Tell us what you're building"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("These choices determine the safest OAuth flow. You can tune advanced settings after creation."))}</p><div class="wizard-grid">
            ${textField(i18n, "Application name", "name", values.name, { required: true, placeholder: "Customer portal" })}
            ${textField(i18n, "Client ID", "client_id", values.clientId, { required: true, placeholder: "customer_portal" })}
            <fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Application kind"))}</legend><div class="choice-cards">
              ${choiceCard(i18n, "client_kind", "application", values.clientKind, "Web application", "Interactive browser sign-in with authorization code and PKCE.")}
              ${choiceCard(i18n, "client_kind", "device", values.clientKind, "Device or CLI", "Input-constrained devices using the OAuth device authorization grant.")}
              ${choiceCard(i18n, "client_kind", "service", values.clientKind, "Machine to machine", "A backend service authenticating without a person.")}
            </div></fieldset>
            <fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("Client authentication"))}</legend><div class="choice-cards choice-cards--two">
              ${choiceCard(i18n, "type", "public", values.type, "Public", "No stored secret. Best for browser, mobile, desktop, and CLI clients.")}
              ${choiceCard(i18n, "type", "confidential", values.type, "Confidential", "Receives a one-time client secret for a trusted backend.")}
            </div></fieldset>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="1"><legend>${escapeHtml(i18n.t("Configure the login flow"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("Callback URLs must match exactly. Local loopback HTTP is allowed for development."))}</p><div class="wizard-grid">
            <div class="field--wide">${textAreaField(i18n, "Redirect URIs", "redirect_uris", values.redirectUris, "One exact callback URL per line.", { required: values.clientKind === "application" })}</div>
            <div class="field--wide">${textAreaField(i18n, "Post-logout redirect URIs", "post_logout_redirect_uris", values.postLogoutRedirectUris, "Where users may return after RP-Initiated Logout.")}</div>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="2"><legend>${escapeHtml(i18n.t("Choose access"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("Grant only the scopes and API audiences this application needs."))}</p><div class="wizard-grid">
            <div>${textAreaField(i18n, "Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line, such as openid, profile, or api.read.", { required: true })}</div>
            <div>${textAreaField(i18n, "Allowed grant types", "allowed_grant_types", values.allowedGrantTypes, GRANT_HINT, { required: true })}</div>
            <fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("APIs"))}</legend>${resourceChoices(i18n, resources, values.allowedResources)}<p class="form-hint">${escapeHtml(i18n.t("Choose at least one enabled API. The wizard suggests one whose scopes match the selected application kind."))}</p></fieldset>
            <div class="field--wide">${textField(i18n, "Default resource", "default_resource", values.defaultResource, { placeholder: "https://api.example.com" })}</div>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="3"><legend>${escapeHtml(i18n.t("Review and create"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("Check the important values before registering the application. Authorization-code clients always use S256 PKCE."))}</p><dl class="wizard-review">
            ${reviewRow("Name", "name", values.name)}${reviewRow("Client ID", "client_id", values.clientId)}${reviewRow("Kind", "client_kind", i18n.t(label(values.clientKind)))}${reviewRow("Authentication", "type", i18n.t(label(values.type)))}${reviewRow("Redirect URIs", "redirect_uris", values.redirectUris)}${reviewRow("Scopes", "allowed_scopes", values.allowedScopes)}${reviewRow("Grant types", "allowed_grant_types", values.allowedGrantTypes)}${reviewRow("Resources", "allowed_resources", values.allowedResources)}
          </dl></fieldset>
          <div class="wizard-actions"><button class="btn btn--ghost btn--auto" type="button" data-wizard-back hidden>${escapeHtml(i18n.t("Back"))}</button><div class="wizard-actions__right"><button class="btn btn--primary btn--auto" type="button" data-wizard-next>${escapeHtml(i18n.t("Continue"))}</button><button class="btn btn--primary btn--auto" type="submit" data-wizard-submit hidden>${escapeHtml(i18n.t("Create application"))}</button></div></div>
        </div>
      </div>
    </form>
  </section>`
  return consoleShell(i18n.t("New application"), chrome, content)
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
  const { i18n } = chrome
  const isNew = client === null
  const values = feedback?.values ?? initialClientFormValues(client)
  const action = isNew ? "/console/clients" : `/console/clients/${escapeHtml(client.clientId)}`
  const identity = isNew
    ? `${textField(i18n, "Client ID", "client_id", values.clientId, { required: true, placeholder: "my_app" })}
       ${selectField(
         i18n,
         "Type",
         "type",
         [
           { value: "public", label: "Public" },
           { value: "confidential", label: "Confidential (gets a secret)" },
         ],
         values.type,
       )}
       ${selectField(
         i18n,
         "Kind",
         "client_kind",
         [
           { value: "application", label: "Application" },
           { value: "device", label: "Device" },
           { value: "service", label: "Service" },
         ],
         values.clientKind,
       )}`
    : `${textField(i18n, "Client ID", "client_id_display", client.clientId, { readonly: true })}
       <p class="form-hint">${escapeHtml(i18n.t("Type:"))} ${escapeHtml(i18n.t(label(client.type)))} · ${escapeHtml(i18n.t("Kind:"))} ${escapeHtml(i18n.t(label(client.clientKind)))} · ${escapeHtml(i18n.t("Secret:"))} ${escapeHtml(i18n.t(client.clientSecretHash === null ? "none" : "set"))}</p>`
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${isNew ? escapeHtml(i18n.t("New client")) : escapeHtml(client.name)}</h2><p class="panel__desc">${escapeHtml(i18n.t(isNew ? "Register an OAuth client." : "Edit client configuration."))}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/clients">${escapeHtml(i18n.t("Back to applications"))}</a>
  </div>
  <section class="panel"><div class="panel__body">
    ${errorHtml}
    <form method="post" action="${action}" class="form-grid">
      ${csrfField(csrfToken)}
      ${identity}
      ${textField(i18n, "Display name", "name", values.name, { required: true })}
      ${textAreaField(i18n, "Redirect URIs", "redirect_uris", values.redirectUris, "One URL per line.")}
      ${textAreaField(i18n, "Post-logout redirect URIs", "post_logout_redirect_uris", values.postLogoutRedirectUris, "Exact RP-Initiated Logout destinations, one per line.")}
      ${textAreaField(i18n, "Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line.")}
      ${textAreaField(i18n, "Allowed grant types", "allowed_grant_types", values.allowedGrantTypes, GRANT_HINT)}
      ${textAreaField(i18n, "Allowed resources", "allowed_resources", values.allowedResources, "Resource URIs, one per line.")}
      ${textField(i18n, "Default resource", "default_resource", values.defaultResource)}
      <p class="form-hint">${escapeHtml(i18n.t("Authorization-code clients always require PKCE with S256."))}</p>
      <div><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t(isNew ? "Create client" : "Save changes"))}</button></div>
    </form>
  </div></section>
  ${isNew ? "" : renderClientDangerZone(i18n, client, csrfToken)}`
  return consoleShell(isNew ? i18n.t("New client") : client.name, chrome, content)
}

function renderClientDangerZone(i18n: I18n, client: OAuthClient, csrfToken: string): string {
  const id = escapeHtml(client.clientId)
  const toggle = client.enabled
    ? `<form method="post" action="/console/clients/${id}/disable">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Disable"))}</button></form>`
    : `<form method="post" action="/console/clients/${id}/enable">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Enable"))}</button></form>`
  const rotate =
    client.type === "confidential"
      ? `<a class="btn btn--ghost btn--auto" href="/console/clients/${id}/rotate-secret">${escapeHtml(i18n.t("Rotate secret"))}</a>`
      : ""
  return `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Manage"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Enable, disable, rotate the secret, or delete this client."))}</p></div></div>
    <div class="panel__body"><div class="actions actions--start">
      ${toggle}
      ${rotate}
      <a class="btn btn--danger btn--auto" href="/console/clients/${id}/delete">${escapeHtml(i18n.t("Delete client"))}</a>
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
  const { i18n } = chrome
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
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(error))}</div>`
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(i18n.t(title))}</h2><p class="panel__desc">${escapeHtml(client.name)}</p></div>
    <a class="btn btn--ghost btn--sm" href="/console/clients/${id}">${escapeHtml(i18n.t("Cancel"))}</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Confirm high-impact change"))}</h2><p class="panel__desc">${escapeHtml(i18n.t(consequence))}</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/clients/${id}/${action}" class="form-grid">
        ${csrfField(csrfToken)}
        ${textField(i18n, i18n.t("Type {value} to confirm", { value: client.clientId }), "confirmation", "", { required: true })}
        <div><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t(button))}</button></div>
      </form>
    </div>
  </section>`
  return consoleShell(i18n.t(title), chrome, content)
}

export function renderClientSecret(
  chrome: ConsoleChrome,
  clientId: string,
  secret: string,
): string {
  const { i18n } = chrome
  const content = `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Client secret"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Copy this now — it is shown once and cannot be retrieved again."))}</p></div></div>
    <div class="panel__body">
      <p class="form-hint">${escapeHtml(i18n.t("Secret for {clientId}", { clientId }))}</p>
      <div class="secret">${escapeHtml(secret)}</div>
      <p class="secret-done"><a class="btn btn--primary btn--sm btn--auto" href="/console/clients/${escapeHtml(clientId)}">${escapeHtml(i18n.t("Done"))}</a></p>
    </div>
  </section>`
  return consoleShell(i18n.t("Client secret"), chrome, content)
}
