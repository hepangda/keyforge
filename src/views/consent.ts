import type { I18n } from "../i18n"
import { brandHeader, escapeHtml, htmlLayout, icons, permissionList } from "./layout"

export type ConsentPageParams = {
  readonly i18n: I18n
  readonly csrfToken: string
  readonly clientName: string
  readonly scopes: readonly string[]
  readonly resource: string
  readonly hiddenFields: Readonly<Record<string, string>>
}

export function renderConsentPage(params: ConsentPageParams): string {
  const { i18n } = params
  const hidden = Object.entries(params.hiddenFields)
    .map(
      ([key, value]) =>
        `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`,
    )
    .join("\n  ")
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Authorize {client}", { client: params.clientName }))}</h1>
    <p class="lead"><strong>${escapeHtml(params.clientName)}</strong> ${escapeHtml(i18n.t("wants to access your KeyForge account."))}</p>
  </div>
  ${permissionList(i18n, params.scopes)}
  <div class="callout">${escapeHtml(i18n.t("Resource"))} <span class="mono">${escapeHtml(params.resource)}</span></div>
  <form method="post" action="/oauth/authorize/decision">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    ${hidden}
    <div class="btn-row">
      <button class="btn btn--ghost" type="submit" name="decision" value="deny">${escapeHtml(i18n.t("Deny"))}</button>
      <button class="btn btn--primary" type="submit" name="decision" value="approve">${escapeHtml(i18n.t("Allow access"))}</button>
    </div>
  </form>
</main>`
  return htmlLayout(i18n, i18n.t("Authorize — KeyForge"), body)
}

export function renderErrorPage(i18n: I18n, description: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark result-mark--muted">${icons.cross}</div>
    <h1>${escapeHtml(i18n.t("Request error"))}</h1>
  </div>
  <div class="alert" role="alert">${icons.alert}<div>${escapeHtml(i18n.t(description))}</div></div>
  <p class="foot"><a class="link-quiet" href="/login">${escapeHtml(i18n.t("Return to sign in"))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Error — KeyForge"), body)
}
