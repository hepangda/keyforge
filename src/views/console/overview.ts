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
  const { i18n } = chrome
  const setup = [
    {
      done: stats.clients > 0,
      title: "Register an application",
      description: "Choose an OAuth flow and configure callback URLs.",
      href: "/console/clients/new",
      action: "Create application",
    },
    {
      done: stats.users > 1,
      title: "Provision your first user",
      description: "Create a username and choose password, invitation, and group access.",
      href: "/console/users/new",
      action: "Add user",
    },
    {
      done: stats.resources > 0,
      title: "Define an API",
      description: "Register an audience and the scopes applications may request.",
      href: "/console/resources/new",
      action: "Create API",
    },
    {
      done: recent.length > 0,
      title: "Review security activity",
      description: "Use the audit log to verify setup and sign-in events.",
      href: "/console/audit",
      action: "Open audit log",
    },
  ]
  const completed = setup.filter((step) => step.done).length
  const setupRows = setup
    .map(
      (step, index) => `<li class="setup-step${step.done ? " setup-step--done" : ""}">
      <span class="setup-step__mark">${step.done ? "✓" : index + 1}</span>
      <div><h3>${escapeHtml(i18n.t(step.title))}</h3><p>${escapeHtml(i18n.t(step.description))}</p></div>
      <a class="btn btn--ghost btn--tiny" href="${step.href}">${escapeHtml(i18n.t(step.done ? "Review" : step.action))}</a>
    </li>`,
    )
    .join("")
  const tiles = TILES.map(
    (tile) =>
      `<a class="stat" href="${tile.href}"><span class="stat__num">${stats[tile.key]}</span><span class="stat__label">${escapeHtml(i18n.t(tile.label))}</span></a>`,
  ).join("")
  const rows = recent.map((entry) => [
    `<span class="mono">${escapeHtml(fmtDateTime(i18n, entry.createdAt))}</span>`,
    `<span class="mono">${escapeHtml(entry.eventType)}</span>`,
    entry.success === null ? "—" : statusBadge(i18n, entry.success, "ok", "fail"),
    entry.actorUserId !== null
      ? `<span class="mono">${escapeHtml(entry.actorUserId)}</span>`
      : entry.actorClientId !== null
        ? `<span class="mono">${escapeHtml(entry.actorClientId)}</span>`
        : "—",
    entry.userId === null ? "—" : `<span class="mono">${escapeHtml(entry.userId)}</span>`,
  ])
  const content = `<section class="setup-card">
    <div class="setup-card__intro"><h2>${escapeHtml(i18n.t(completed === setup.length ? "Your workspace is ready" : "Get KeyForge ready"))}</h2><p>${escapeHtml(i18n.t(completed === setup.length ? "Core configuration is in place. Revisit any step when your integration changes." : "Follow these steps to move from a new tenant to a working sign-in flow."))}</p><div class="setup-progress" role="progressbar" aria-label="${escapeHtml(i18n.t("Setup progress"))}" aria-valuemin="0" aria-valuemax="${setup.length}" aria-valuenow="${completed}"><span style="width:${(completed / setup.length) * 100}%"></span></div><span class="setup-card__count">${escapeHtml(i18n.t("{completed} of {total} steps complete", { completed, total: setup.length }))}</span></div>
    <ol class="setup-list">${setupRows}</ol>
  </section>
  <div class="stat-grid">${tiles}</div>
  <section class="panel">
    <div class="panel__head">
      <div><h2 class="panel__title">${escapeHtml(i18n.t("Recent activity"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("The latest security events across the server."))}</p></div>
      <a class="btn btn--ghost btn--sm" href="/console/audit">${escapeHtml(i18n.t("View all"))}</a>
    </div>
    <div class="panel__body">${dataTable(i18n, ["Time", "Event", "Result", "Actor", "Subject user"], rows, "No activity recorded yet.")}</div>
  </section>`
  return consoleShell(i18n.t("Overview"), chrome, content)
}
