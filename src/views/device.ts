import type { I18n } from "../i18n"
import { brandHeader, escapeHtml, htmlLayout, icons, permissionList } from "./layout"

export function renderDeviceCodeEntryPage(i18n: I18n, error?: string): string {
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="alert" role="alert">${icons.alert}<div>${escapeHtml(i18n.t(error))}</div></div>`
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Connect a device"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("Enter the code shown on your device to continue."))}</p>
  </div>
  ${errorHtml}
  <form method="get" action="/device" autocomplete="off">
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("Device code"))}</span>
      <input class="input input--code" type="text" name="user_code" required
        autocomplete="one-time-code" placeholder="ABCD-EFGH" inputmode="text"
        autocapitalize="characters" spellcheck="false" autofocus>
    </label>
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Continue"))}</button>
  </form>
</main>`
  return htmlLayout(i18n, i18n.t("Connect a device — KeyForge"), body)
}

export type DeviceConfirmParams = {
  readonly i18n: I18n
  readonly csrfToken: string
  readonly userCode: string
  readonly clientName: string
  readonly scopes: readonly string[]
  readonly resource: string
}

export function renderDeviceConfirmPage(params: DeviceConfirmParams): string {
  const { i18n } = params
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Authorize {client}", { client: params.clientName }))}</h1>
    <p class="lead">${escapeHtml(i18n.t("Confirm you want to grant access to this device."))}</p>
  </div>
  <div class="callout">${escapeHtml(i18n.t("Device code"))} <span class="mono">${escapeHtml(params.userCode)}</span></div>
  ${permissionList(i18n, params.scopes)}
  <div class="callout">${escapeHtml(i18n.t("Resource"))} <span class="mono">${escapeHtml(params.resource)}</span></div>
  <form method="post" action="/device/confirm">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    <input type="hidden" name="user_code" value="${escapeHtml(params.userCode)}">
    <div class="btn-row">
      <button class="btn btn--ghost" type="submit" name="decision" value="deny">${escapeHtml(i18n.t("Deny"))}</button>
      <button class="btn btn--primary" type="submit" name="decision" value="approve">${escapeHtml(i18n.t("Allow access"))}</button>
    </div>
  </form>
</main>`
  return htmlLayout(i18n, i18n.t("Authorize device — KeyForge"), body)
}

export function renderDeviceResultPage(i18n: I18n, kind: "approved" | "denied"): string {
  const approved = kind === "approved"
  const heading = approved ? "Device connected" : "Request denied"
  const message = approved
    ? "You can return to your device — it's now signed in."
    : "The device request was denied. It's safe to close this page."
  const mark = approved
    ? `<div class="result-mark">${icons.check}</div>`
    : `<div class="result-mark result-mark--muted">${icons.cross}</div>`
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    ${mark}
    <h1>${escapeHtml(i18n.t(heading))}</h1>
    <p class="lead">${escapeHtml(i18n.t(message))}</p>
  </div>
</main>`
  return htmlLayout(i18n, i18n.t("Device — KeyForge"), body)
}
