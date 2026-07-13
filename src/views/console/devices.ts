import type { AdminDeviceSession } from "../../db/queries/admin-devices"
import { escapeHtml } from "../layout"
import { csrfField, dataTable, fmtDateTime, pager } from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

const REVOCABLE: ReadonlySet<string> = new Set(["pending", "approved"])

function statusChip(status: string): string {
  return `<span class="tag">${escapeHtml(status)}</span>`
}

export function renderDevicesList(
  chrome: ConsoleChrome,
  devices: readonly AdminDeviceSession[],
  csrfToken: string,
  limit: number,
  offset: number,
  hasNext: boolean,
): string {
  const rows = devices.map((device) => {
    const action = REVOCABLE.has(device.status)
      ? `<form method="post" action="/console/devices/${escapeHtml(device.id)}/revoke">${csrfField(csrfToken)}<button class="btn btn--danger btn--tiny" type="submit">Revoke</button></form>`
      : ""
    return [
      `<span class="mono">${escapeHtml(device.clientId)}</span>`,
      statusChip(device.status),
      device.userId === null ? "—" : `<span class="mono">${escapeHtml(device.userId)}</span>`,
      `<span class="mono">${escapeHtml(fmtDateTime(device.expiresAt))}</span>`,
      `<div class="actions">${action}</div>`,
    ]
  })
  const content = `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">Device sessions</h2><p class="panel__desc">Device authorization grants and their current status.</p></div></div>
    ${dataTable(["Client", "Status", "User", "Expires", ""], rows, "No device sessions.")}
    <div class="panel__body">${pager("/console/devices", limit, offset, devices.length, hasNext)}</div>
  </section>`
  return consoleShell("Device sessions — Admin console", chrome, content)
}
