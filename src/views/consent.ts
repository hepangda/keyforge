import type { I18n } from "../i18n"
import type { User } from "../types/domain"
import { avatarMarkup, brandHeader, escapeHtml, htmlLayout, icons, permissionList } from "./layout"

export type ConsentPageParams = {
  readonly i18n: I18n
  readonly csrfToken: string
  readonly clientName: string
  readonly clientId: string
  readonly metadataClient: boolean
  readonly redirectUri: string
  readonly scopes: readonly string[]
  readonly resource: string
  readonly resourceName: string
  readonly consentMode: "first" | "step_up" | "metadata_changed" | "forced"
  readonly elevatedScopes: readonly string[]
  readonly user: User
  readonly authorizationReturnTo: string
  readonly hiddenFields: Readonly<Record<string, string>>
}

export function renderConsentPage(params: ConsentPageParams): string {
  const { i18n } = params
  const displayName = params.user.name ?? params.user.alias
  const avatar = avatarMarkup(params.user)
  const clientIdentity = params.metadataClient
    ? `<div class="callout">${escapeHtml(i18n.t("Client identity"))} <a class="mono" href="${escapeHtml(params.clientId)}" rel="noreferrer">${escapeHtml(params.clientId)}</a></div>
  <div class="callout">${escapeHtml(i18n.t("Verified client host"))} <span class="mono">${escapeHtml(new URL(params.clientId).host)}</span></div>
  <div class="callout">${escapeHtml(i18n.t("Redirect destination"))} <span class="mono">${escapeHtml(params.redirectUri)}</span>${new URL(params.redirectUri).protocol === "http:" ? `<br><strong>${escapeHtml(i18n.t("This client will return to a local application on your device. A different local process could impersonate that callback."))}</strong>` : ""}</div>`
    : ""
  const consentNotice =
    params.consentMode === "metadata_changed"
      ? "This client's metadata changed. Review its identity, callback, and permissions again."
      : params.consentMode === "step_up"
        ? "This client is requesting additional permissions."
        : params.consentMode === "forced"
          ? "This client requested renewed confirmation."
          : "This is the first authorization for this client and resource."
  const elevatedConfirmation = params.scopes.includes("mcp.tools.execute")
    ? `<div class="alert" role="alert">${icons.alert}<div><strong>${escapeHtml(i18n.t("Elevated permission"))}</strong><br>${escapeHtml(i18n.t("mcp.tools.execute can run actions and change data through this MCP server."))}</div></div><label class="checkline"><input type="checkbox" name="confirm_elevated" value="yes" required>${escapeHtml(i18n.t("I explicitly allow this client to execute MCP tools."))}</label>`
    : ""
  const hidden = Object.entries(params.hiddenFields)
    .map(
      ([key, value]) =>
        `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`,
    )
    .join("\n  ")
  const body = `<main class="card consent-card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Authorize {client}", { client: params.clientName }))}</h1>
    <p class="lead"><strong>${escapeHtml(params.clientName)}</strong> ${escapeHtml(i18n.t("wants to access your KeyForge account."))}</p>
  </div>
  <div class="consent-account">
    ${avatar}
    <div class="consent-account__body"><span>${escapeHtml(i18n.t("Signed in as"))}</span><strong>${escapeHtml(displayName)}</strong><small>@${escapeHtml(params.user.alias)} · ${escapeHtml(params.user.email)}</small></div>
    <form class="consent-account__actions" method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
      <input type="hidden" name="continue_to" value="${escapeHtml(params.authorizationReturnTo)}">
      <button class="link-button" type="submit" name="intent" value="switch_account">${escapeHtml(i18n.t("Switch account"))}</button>
      <button class="link-button link-button--quiet" type="submit" name="intent" value="sign_out">${escapeHtml(i18n.t("Sign out"))}</button>
    </form>
  </div>
  <div class="callout"><strong>${escapeHtml(i18n.t(consentNotice))}</strong>${params.elevatedScopes.length === 0 ? "" : `<br>${escapeHtml(i18n.t("New permissions"))}: <span class="mono">${escapeHtml(params.elevatedScopes.join(" "))}</span>`}</div>
  ${permissionList(i18n, params.scopes)}
  ${clientIdentity}
  <div class="callout">${escapeHtml(i18n.t("Target resource"))} <strong>${escapeHtml(params.resourceName)}</strong><br><span class="mono">${escapeHtml(params.resource)}</span></div>
  <form method="post" action="/oauth/authorize/decision">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    ${hidden}
    ${elevatedConfirmation}
    <div class="btn-row">
      <button class="btn btn--ghost" type="submit" name="decision" value="deny">${escapeHtml(i18n.t("Deny"))}</button>
      <button class="btn btn--primary" type="submit" name="decision" value="approve">${escapeHtml(i18n.t("Allow access"))}</button>
    </div>
  </form>
  <p class="consent-revoke-note">${escapeHtml(i18n.t("Allowing access uses the signed-in account shown above. You can revoke access later in your account settings."))}</p>
</main>`
  return htmlLayout(
    i18n,
    i18n.t("Authorize — KeyForge"),
    body,
    `.consent-card{padding:1.25rem 1.4rem}.consent-card .head{margin-bottom:.85rem}.consent-card .brand{flex-direction:row;justify-content:center;gap:.55rem;margin-bottom:.75rem}.consent-card .seal{width:34px;height:34px}.consent-card .brand__name{font-size:.9rem}.consent-card h1{font-size:1.3rem}.consent-card .lead{margin-top:.3rem;font-size:.86rem}.consent-account{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:.7rem;margin:.8rem 0;padding:.7rem .75rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}.consent-account .avatar{width:36px;height:36px;font-size:.8rem}.consent-account__body{min-width:0;display:grid;line-height:1.25}.consent-account__body>span{font-size:.68rem;color:var(--ink-3)}.consent-account__body>strong{font-size:.86rem;overflow-wrap:anywhere}.consent-account__body>small{margin-top:.1rem;color:var(--ink-2);font-size:.72rem;overflow-wrap:anywhere}.consent-account__actions{display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;justify-content:flex-end}.link-button{padding:0;color:var(--brass);background:none;border:0;font:600 .74rem/1.4 var(--font-sans);cursor:pointer}.link-button:hover{text-decoration:underline;text-underline-offset:2px}.link-button:focus-visible{outline:none;box-shadow:var(--focus);border-radius:3px}.link-button--quiet{color:var(--ink-2)}.consent-card .perm{margin:.75rem 0}.consent-card .perm li{padding:.55rem .75rem}.consent-card .perm__desc{font-size:.75rem}.consent-card .callout{margin:.75rem 0;padding:.65rem .75rem;font-size:.78rem}.consent-card .btn{padding:.68rem .85rem;font-size:.88rem}.consent-revoke-note{margin:.7rem 0 0;color:var(--ink-3);font-size:.73rem;text-align:center}@media(max-width:720px){.consent-account{grid-template-columns:auto minmax(0,1fr)}.consent-account__actions{grid-column:1/-1;justify-content:flex-start;padding-left:2.7rem}}`,
  )
}

export function renderErrorPage(
  i18n: I18n,
  description: string,
  actionHref: string,
  actionLabel: string,
): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark result-mark--muted">${icons.cross}</div>
    <h1>${escapeHtml(i18n.t("Request error"))}</h1>
  </div>
  <div class="alert" role="alert">${icons.alert}<div>${escapeHtml(i18n.t(description))}</div></div>
  <p class="foot"><a class="link-quiet" href="${escapeHtml(actionHref)}">${escapeHtml(i18n.t(actionLabel))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Error — KeyForge"), body)
}
