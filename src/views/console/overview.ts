import type { AuditLogEntry } from "../../db/queries/audit"
import { escapeHtml } from "../layout"
import { dataTable, fmtDateTime, statusBadge } from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

export type ConsoleStats = {
  readonly users: number
  readonly clients: number
  readonly resources: number
  readonly devices: number
}

const TILES: readonly {
  readonly key: keyof ConsoleStats
  readonly label: string
  readonly href: string
}[] = [
  { key: "users", label: "Users", href: "/console/users" },
  { key: "clients", label: "OAuth clients", href: "/console/clients" },
  { key: "resources", label: "Resources", href: "/console/resources" },
  { key: "devices", label: "Device sessions", href: "/console/devices" },
]

export function renderOverview(
  chrome: ConsoleChrome,
  stats: ConsoleStats,
  recent: readonly AuditLogEntry[],
): string {
  const tiles = TILES.map(
    (tile) =>
      `<a class="stat" href="${tile.href}"><span class="stat__num">${stats[tile.key]}</span><span class="stat__label">${escapeHtml(tile.label)}</span></a>`,
  ).join("")
  const rows = recent.map((entry) => [
    `<span class="mono">${escapeHtml(fmtDateTime(entry.createdAt))}</span>`,
    `<span class="mono">${escapeHtml(entry.eventType)}</span>`,
    entry.success === null ? "—" : statusBadge(entry.success, "ok", "fail"),
    entry.actorUserId !== null
      ? `<span class="mono">${escapeHtml(entry.actorUserId)}</span>`
      : entry.actorClientId !== null
        ? `<span class="mono">${escapeHtml(entry.actorClientId)}</span>`
        : "—",
    entry.userId === null ? "—" : `<span class="mono">${escapeHtml(entry.userId)}</span>`,
  ])
  const content = `<div class="stat-grid">${tiles}</div>
  <section class="panel">
    <div class="panel__head">
      <div><h2 class="panel__title">Recent activity</h2><p class="panel__desc">The latest security events across the server.</p></div>
      <a class="btn btn--ghost btn--sm" href="/console/audit">View all</a>
    </div>
    <div class="panel__body">${dataTable(["Time", "Event", "Result", "Actor", "Subject user"], rows, "No activity recorded yet.")}</div>
  </section>`
  return consoleShell("Overview — Admin console", chrome, content)
}
