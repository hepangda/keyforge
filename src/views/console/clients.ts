import type { I18n } from "../../i18n"
import type { ClientKind, ClientType, OAuthClient, OAuthResource } from "../../types/domain"
import { escapeHtml } from "../layout"
import { searchPicker } from "../search-picker"
import {
  csrfField,
  dataTable,
  pager,
  secondaryTabs,
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

export function renderClientsList(
  chrome: ConsoleChrome,
  clients: readonly OAuthClient[],
  limit: number,
  offset: number,
  hasNext: boolean,
): string {
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
  <section class="panel">${dataTable(i18n, ["Client ID", "Name", "Kind", "Status", ""], rows, "No clients yet.")}<div class="panel__body">${pager(i18n, "/console/clients", limit, offset, clients.length, hasNext)}</div></section>`
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

export type ClientFormField =
  | "client_id"
  | "name"
  | "redirect_uris"
  | "post_logout_redirect_uris"
  | "allowed_scopes"
  | "allowed_grant_types"
  | "allowed_resources"
  | "default_resource"

export type ClientFormFeedback = {
  readonly values: ClientFormValues
  readonly initialStep: 0 | 1 | 2 | 3
  readonly field: ClientFormField | null
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
  includeSelectedDisabled = false,
): string {
  const selectedResources = new Set(
    selected
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean),
  )
  const candidates = resources.filter(
    (resource) =>
      resource.enabled || (includeSelectedDisabled && selectedResources.has(resource.resourceUri)),
  )
  if (candidates.length === 0) {
    return `<div class="wizard-empty">${escapeHtml(i18n.t("No enabled APIs are available."))} <a href="/console/resources/new">${escapeHtml(i18n.t("Create an API first"))}</a>.</div>`
  }
  return searchPicker(
    i18n,
    {
      id: "client-resource-access",
      name: "allowed_resources",
      label: "APIs",
      placeholder: "Search APIs by name or resource URI",
      emptySelection: "No APIs selected.",
      required: true,
    },
    candidates.map((resource, index) => ({
      value: resource.resourceUri,
      title: resource.name,
      detail: `${resource.allowedScopes.join(", ")}${resource.enabled ? "" : ` · ${i18n.t("Disabled")}`}`,
      meta: resource.resourceUri,
      selected: selectedResources.has(resource.resourceUri),
      recommended: resource.enabled && index < 6,
      data: { "resource-scopes": resource.allowedScopes.join(" ") },
    })),
  )
}

function renderNewClientWizard(
  chrome: ConsoleChrome,
  csrfToken: string,
  resources: readonly OAuthResource[],
  feedback?: ClientFormFeedback,
): string {
  const { i18n } = chrome
  const enabledResources = resources.filter((resource) => resource.enabled)
  if (enabledResources.length === 0) {
    const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Create an application"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Create an enabled API before registering an application."))}</p></div></div><section class="panel"><div class="panel__body"><div class="wizard-empty">${escapeHtml(i18n.t("Applications must reference at least one enabled API."))}</div><div class="actions actions--start"><a class="btn btn--primary btn--auto" href="/console/resources/new?return_to=%2Fconsole%2Fclients%2Fnew">${escapeHtml(i18n.t("Create API"))}</a><a class="btn btn--ghost btn--auto back-link" href="/console/clients">${escapeHtml(i18n.t("Back to applications"))}</a></div></div></section>`
    return consoleShell(i18n.t("New application"), chrome, content)
  }
  const values = feedback?.values ?? initialClientFormValues(null, resources)
  const fieldError = (field: ClientFormField) =>
    feedback?.field === field ? feedback.error : undefined
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert" tabindex="-1" data-error-summary>${escapeHtml(i18n.t(feedback.error))}</div>`
  const stepNames = ["Application", "Login flow", "Access", "Review"]
  const markers = stepNames
    .map(
      (name, index) =>
        `<li class="wizard-step${index === 0 ? " wizard-step--active" : ""}" data-wizard-marker="${index}"><span>${index + 1}</span><strong>${escapeHtml(i18n.t(name))}</strong></li>`,
    )
    .join("")
  const reviewRow = (labelText: string, field: string, value: string) =>
    `<div class="wizard-review__row"><dt>${escapeHtml(i18n.t(labelText))}</dt><dd data-review-for="${field}">${escapeHtml(value || "—")}</dd></div>`
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Create an application"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("A guided setup for the OAuth flow, redirect URLs, and API access."))}</p></div><a class="btn btn--ghost btn--sm back-link" href="/console/clients">${escapeHtml(i18n.t("Back to applications"))}</a></div>
  <section class="panel">
    ${errorHtml === "" ? "" : `<div class="panel__body">${errorHtml}</div>`}
    <form method="post" action="/console/clients" data-console-wizard data-initial-step="${feedback?.initialStep ?? 0}" data-label-application="${escapeHtml(i18n.t("Web application"))}" data-label-device="${escapeHtml(i18n.t("Device or CLI"))}" data-label-service="${escapeHtml(i18n.t("Machine to machine"))}" data-label-public="${escapeHtml(i18n.t("Public"))}" data-label-confidential="${escapeHtml(i18n.t("Confidential"))}">
      ${csrfField(csrfToken)}
      <div class="wizard-shell">
        <aside class="wizard-rail"><h3>${escapeHtml(i18n.t("Application setup"))}</h3><ol class="wizard-steps">${markers}</ol></aside>
        <div class="wizard-main">
          <fieldset class="wizard-panel wizard-panel--active" data-wizard-step="0"><legend>${escapeHtml(i18n.t("Tell us what you're building"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("These choices determine the safest OAuth flow. You can tune advanced settings after creation."))}</p><div class="wizard-grid">
            ${textField(i18n, "Application name", "name", values.name, { required: true, placeholder: "Customer portal", error: fieldError("name") })}
            ${textField(i18n, "Client ID", "client_id", values.clientId, { required: true, placeholder: "customer_portal", error: fieldError("client_id") })}
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
            <div class="field--wide">${textAreaField(i18n, "Redirect URIs", "redirect_uris", values.redirectUris, "One exact callback URL per line.", { required: values.clientKind === "application", error: fieldError("redirect_uris") })}</div>
            <div class="field--wide">${textAreaField(i18n, "Post-logout redirect URIs", "post_logout_redirect_uris", values.postLogoutRedirectUris, "Where users may return after RP-Initiated Logout.", { error: fieldError("post_logout_redirect_uris") })}</div>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="2"><legend>${escapeHtml(i18n.t("Choose access"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("Grant only the scopes and API audiences this application needs."))}</p><div class="wizard-grid">
            <div>${textAreaField(i18n, "Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line, such as openid, profile, or api.read.", { required: true, error: fieldError("allowed_scopes") })}</div>
            <div>${textAreaField(i18n, "Allowed grant types", "allowed_grant_types", values.allowedGrantTypes, GRANT_HINT, { required: true, error: fieldError("allowed_grant_types") })}</div>
            <fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("APIs"))}</legend>${resourceChoices(i18n, resources, values.allowedResources)}<p class="form-hint">${escapeHtml(i18n.t("Choose at least one enabled API. The wizard suggests one whose scopes match the selected application kind."))}</p></fieldset>
            <div class="field--wide">${textField(i18n, "Default resource", "default_resource", values.defaultResource, { placeholder: "https://api.example.com", error: fieldError("default_resource") })}</div>
          </div></fieldset>
          <fieldset class="wizard-panel" data-wizard-step="3"><legend>${escapeHtml(i18n.t("Review and create"))}</legend><p class="wizard-panel__lead">${escapeHtml(i18n.t("Check the important values before registering the application. Authorization-code clients always use S256 PKCE."))}</p><dl class="wizard-review">
            ${reviewRow("Name", "name", values.name)}${reviewRow("Client ID", "client_id", values.clientId)}${reviewRow("Kind", "client_kind", i18n.t(label(values.clientKind)))}${reviewRow("Authentication", "type", i18n.t(label(values.type)))}${reviewRow("Redirect URIs", "redirect_uris", values.redirectUris)}${reviewRow("Scopes", "allowed_scopes", values.allowedScopes)}${reviewRow("Grant types", "allowed_grant_types", values.allowedGrantTypes)}${reviewRow("Resources", "allowed_resources", values.allowedResources)}
          </dl></fieldset>
          <div class="wizard-actions"><button class="btn btn--ghost btn--auto" type="button" data-wizard-back hidden>${escapeHtml(i18n.t("Back"))}</button><div class="wizard-actions__right"><button class="btn btn--primary btn--auto" type="button" data-wizard-next hidden>${escapeHtml(i18n.t("Continue"))}</button><button class="btn btn--primary btn--auto" type="submit" data-wizard-submit>${escapeHtml(i18n.t("Create application"))}</button></div></div>
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
  return client === null
    ? renderNewClientWizard(chrome, csrfToken, resources, feedback)
    : renderClientDetail(chrome, client, "settings", csrfToken, resources, feedback)
}

export type ClientDetailView = "settings" | "access" | "security"

export function renderClientDetail(
  chrome: ConsoleChrome,
  client: OAuthClient,
  view: ClientDetailView,
  csrfToken: string,
  resources: readonly OAuthResource[] = [],
  feedback?: ClientFormFeedback,
): string {
  const { i18n } = chrome
  const id = escapeHtml(client.clientId)
  const values = feedback?.values ?? initialClientFormValues(client)
  const errorHtml =
    feedback === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(feedback.error))}</div>`
  const tabs = secondaryTabs(i18n, "Application sections", [
    {
      label: "Settings",
      href: `/console/clients/${id}?view=settings`,
      active: view === "settings",
    },
    { label: "Access", href: `/console/clients/${id}?view=access`, active: view === "access" },
    {
      label: "Security",
      href: `/console/clients/${id}?view=security`,
      active: view === "security",
    },
  ])
  const summary = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(client.name)}</h2><p class="panel__desc"><span class="mono">${id}</span> · ${escapeHtml(i18n.t(label(client.clientKind)))} · ${escapeHtml(i18n.t(label(client.type)))} · ${statusBadge(i18n, client.enabled, "Enabled", "Disabled")}</p></div><div class="actions"><a class="btn btn--ghost btn--sm" href="/console/audit?client_id=${encodeURIComponent(client.clientId)}">${escapeHtml(i18n.t("View audit events"))}</a><a class="btn btn--ghost btn--sm back-link" href="/console/clients">${escapeHtml(i18n.t("Back to applications"))}</a></div></div>${tabs}`
  let panel: string
  if (view === "settings") {
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Settings"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Display name and registered browser redirect destinations."))}</p></div></div><div class="panel__body">${errorHtml}<form method="post" action="/console/clients/${id}/settings" class="form-grid">${csrfField(csrfToken)}${textField(i18n, "Display name", "name", values.name, { required: true })}<div class="field--wide">${textAreaField(i18n, "Redirect URIs", "redirect_uris", values.redirectUris, "One URL per line.")}</div><div class="field--wide">${textAreaField(i18n, "Post-logout redirect URIs", "post_logout_redirect_uris", values.postLogoutRedirectUris, "Exact RP-Initiated Logout destinations, one per line.")}</div><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save changes"))}</button></div></form></div></section>`
  } else if (view === "access") {
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Access"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("OAuth grants, scopes, and API audiences."))}</p></div></div><div class="panel__body">${errorHtml}<form method="post" action="/console/clients/${id}/access" class="form-grid">${csrfField(csrfToken)}${textAreaField(i18n, "Allowed scopes", "allowed_scopes", values.allowedScopes, "One scope per line.")}${textAreaField(i18n, "Allowed grant types", "allowed_grant_types", values.allowedGrantTypes, GRANT_HINT)}<fieldset class="field-cluster field--wide"><legend>${escapeHtml(i18n.t("APIs"))}</legend>${resourceChoices(i18n, resources, values.allowedResources, true)}</fieldset><div class="field--wide">${textField(i18n, "Default resource", "default_resource", values.defaultResource)}</div><div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save access"))}</button></div></form></div></section>`
  } else {
    const toggle = client.enabled
      ? `<a class="btn btn--ghost btn--auto" href="/console/clients/${id}/disable">${escapeHtml(i18n.t("Disable"))}</a>`
      : `<form method="post" action="/console/clients/${id}/enable">${csrfField(csrfToken)}<button class="btn btn--ghost btn--auto" type="submit">${escapeHtml(i18n.t("Enable"))}</button></form>`
    const rotate =
      client.type === "confidential"
        ? `<a class="btn btn--ghost btn--auto" href="/console/clients/${id}/rotate-secret">${escapeHtml(i18n.t("Rotate secret"))}</a>`
        : ""
    panel = `<section class="panel"><div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Security"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Application lifecycle and client-secret actions."))}</p></div></div><div class="panel__body"><div class="actions actions--start">${toggle}${rotate}<a class="btn btn--danger btn--auto" href="/console/clients/${id}/delete">${escapeHtml(i18n.t("Delete client"))}</a></div></div></section>`
  }
  return consoleShell(client.name, chrome, `${summary}${panel}`)
}

export function renderClientActionConfirmation(
  chrome: ConsoleChrome,
  client: OAuthClient,
  csrfToken: string,
  action: "disable" | "rotate-secret" | "delete",
  error?: string,
): string {
  const { i18n } = chrome
  const deleting = action === "delete"
  const disabling = action === "disable"
  const id = escapeHtml(client.clientId)
  const title = deleting
    ? "Delete application?"
    : disabling
      ? "Disable application?"
      : "Rotate client secret?"
  const consequence = deleting
    ? "This permanently removes the application, its grants, consents, and refresh tokens."
    : disabling
      ? "New authorization requests will stop immediately. Existing grants and refresh tokens remain until revoked or expired."
      : "The current secret stops working immediately. Update the application with the new secret before it makes another request."
  const button = deleting
    ? "Delete application"
    : disabling
      ? "Disable application"
      : "Rotate secret"
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="flash flash--warn" role="alert">${escapeHtml(i18n.t(error))}</div>`
  const confirmation = disabling
    ? ""
    : textField(
        i18n,
        i18n.t("Type {value} to confirm", { value: client.clientId }),
        "confirmation",
        "",
        { required: true },
      )
  const content = `<div class="toolbar">
    <div><h2 class="panel__title">${escapeHtml(i18n.t(title))}</h2><p class="panel__desc">${escapeHtml(client.name)}</p></div>
    <a class="btn btn--ghost btn--sm back-link" href="/console/clients/${id}?view=security">${escapeHtml(i18n.t("Back to application"))}</a>
  </div>
  <section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Confirm high-impact change"))}</h2><p class="panel__desc">${escapeHtml(i18n.t(consequence))}</p></div></div>
    <div class="panel__body">
      ${errorHtml}
      <form method="post" action="/console/clients/${id}/${action}" class="form-grid form-grid--single">
        ${csrfField(csrfToken)}
        ${confirmation}
        <div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t(button))}</button></div>
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
      <div class="copy-value"><code class="secret copy-value__text" data-copy-source>${escapeHtml(secret)}</code><button class="btn btn--ghost btn--tiny" type="button" data-copy-value data-copy-success="${escapeHtml(i18n.t("Client secret copied."))}" hidden>${escapeHtml(i18n.t("Copy"))}</button><span class="copy-value__status" data-copy-status role="status" hidden></span></div>
      <p class="secret-done"><a class="btn btn--primary btn--sm btn--auto" href="/console/clients/${escapeHtml(clientId)}?view=security">${escapeHtml(i18n.t("Done"))}</a></p>
    </div>
  </section>`
  return consoleShell(i18n.t("Client secret"), chrome, content)
}
