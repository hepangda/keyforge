import type { AdminDeviceSession } from "../../db/queries/admin-devices"
import type { I18n } from "../../i18n"
import { escapeHtml } from "../layout"
import { csrfField, dataTable, fmtDateTime, pager, scopeTags } from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

const REVOCABLE: ReadonlySet<string> = new Set(["pending", "approved"])

function statusChip(i18n: I18n, status: string): string {
  return `<span class="tag">${escapeHtml(i18n.t(status))}</span>`
}

export function renderDevicesList(
  chrome: ConsoleChrome,
  devices: readonly AdminDeviceSession[],

  limit: number,
  offset: number,
  hasNext: boolean,
): string {
  const { i18n } = chrome
  const rows = devices.map((device) => {
    const action = REVOCABLE.has(device.status)
      ? `<a class="btn btn--danger btn--tiny" href="/console/devices/${escapeHtml(device.id)}/revoke">${escapeHtml(i18n.t("Revoke"))}</a>`
      : ""
    return [
      `<span class="mono">${escapeHtml(device.clientId)}</span>`,
      statusChip(i18n, device.status),
      device.userId === null ? "—" : `<span class="mono">${escapeHtml(device.userId)}</span>`,
      `<span class="mono">${escapeHtml(fmtDateTime(i18n, device.expiresAt))}</span>`,
      `<div class="actions">${action}</div>`,
    ]
  })
  const content = `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Device sessions"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Device authorization grants and their current status."))}</p></div></div>
    ${dataTable(i18n, ["Client", "Status", "User", "Expires", ""], rows, "No device sessions.")}
    <div class="panel__body">${pager(i18n, "/console/devices", limit, offset, devices.length, hasNext)}</div>
  </section>`
  return consoleShell(i18n.t("Device sessions"), chrome, content)
}

export function renderDeviceRevokeConfirmation(
  chrome: ConsoleChrome,
  device: AdminDeviceSession,
  csrfToken: string,
): string {
  const { i18n } = chrome
  const id = escapeHtml(device.id)
  const content = `<div class="toolbar"><div><h2 class="panel__title">${escapeHtml(i18n.t("Revoke device session?"))}</h2><p class="panel__desc"><span class="mono">${escapeHtml(device.clientId)}</span></p></div><a class="btn btn--ghost btn--sm back-link" href="/console/devices">${escapeHtml(i18n.t("Back to devices"))}</a></div><section class="panel"><div class="panel__body"><div class="meta"><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Status"))}</span><span class="meta__val">${statusChip(i18n, device.status)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("User"))}</span><span class="meta__val mono">${escapeHtml(device.userId ?? "—")}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Resource"))}</span><span class="meta__val mono">${escapeHtml(device.resourceUri ?? "—")}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Scopes"))}</span><span class="meta__val">${scopeTags(device.scope.split(" ").filter(Boolean))}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Expires"))}</span><span class="meta__val mono">${escapeHtml(fmtDateTime(i18n, device.expiresAt))}</span></div></div><div class="callout">${escapeHtml(i18n.t("This device authorization can no longer be completed or refreshed."))}</div><form method="post" action="/console/devices/${id}/revoke" class="form-grid form-grid--single">${csrfField(csrfToken)}<div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Revoke device"))}</button></div></form></div></section>`
  return consoleShell(i18n.t("Revoke device session?"), chrome, content)
}
