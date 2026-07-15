import type { AdminDeviceSession } from "../../db/queries/admin-devices"
import type { I18n } from "../../i18n"
import { escapeHtml } from "../layout"
import { csrfField, dataTable, fmtDateTime, pager } from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

const REVOCABLE: ReadonlySet<string> = new Set(["pending", "approved"])

function statusChip(i18n: I18n, status: string): string {
  return `<span class="tag">${escapeHtml(i18n.t(status))}</span>`
}

export function renderDevicesList(
  chrome: ConsoleChrome,
  devices: readonly AdminDeviceSession[],
  csrfToken: string,
  limit: number,
  offset: number,
  hasNext: boolean,
): string {
  const { i18n } = chrome
  const rows = devices.map((device) => {
    const action = REVOCABLE.has(device.status)
      ? `<form method="post" action="/console/devices/${escapeHtml(device.id)}/revoke">${csrfField(csrfToken)}<button class="btn btn--danger btn--tiny" type="submit">${escapeHtml(i18n.t("Revoke"))}</button></form>`
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
