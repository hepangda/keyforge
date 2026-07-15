import type { AuditLogEntry } from "../../db/queries/audit"
import type { I18n } from "../../i18n"
import { escapeHtml } from "../layout"
import { dataTable, fmtDateTime, pager, statusBadge } from "./components"
import { type ConsoleChrome, consoleShell } from "./layout"

export type AuditFilters = {
  readonly eventType: string
  readonly userId: string
  readonly clientId: string
  readonly actorUserId: string
  readonly actorClientId: string
}

function filterInput(i18n: I18n, label: string, name: string, value: string): string {
  return `<label class="field"><span class="field__label">${escapeHtml(i18n.t(label))}</span><input class="input" type="text" name="${name}" value="${escapeHtml(value)}"></label>`
}

function baseHref(filters: AuditFilters): string {
  const params = new URLSearchParams()
  if (filters.eventType !== "") params.set("event_type", filters.eventType)
  if (filters.userId !== "") params.set("user_id", filters.userId)
  if (filters.clientId !== "") params.set("client_id", filters.clientId)
  if (filters.actorUserId !== "") params.set("actor_user_id", filters.actorUserId)
  if (filters.actorClientId !== "") params.set("actor_client_id", filters.actorClientId)
  const query = params.toString()
  return query === "" ? "/console/audit" : `/console/audit?${query}`
}

export function renderAuditList(
  chrome: ConsoleChrome,
  logs: readonly AuditLogEntry[],
  filters: AuditFilters,
  limit: number,
  offset: number,
  hasNext: boolean,
): string {
  const { i18n } = chrome
  const rows = logs.map((entry) => [
    `<span class="mono">${escapeHtml(fmtDateTime(i18n, entry.createdAt))}</span>`,
    `<span class="mono">${escapeHtml(entry.eventType)}</span>`,
    entry.success === null ? "—" : statusBadge(i18n, entry.success, "ok", "fail"),
    entry.actorUserId === null ? "—" : `<span class="mono">${escapeHtml(entry.actorUserId)}</span>`,
    entry.actorClientId === null
      ? "—"
      : `<span class="mono">${escapeHtml(entry.actorClientId)}</span>`,
    entry.userId === null ? "—" : `<span class="mono">${escapeHtml(entry.userId)}</span>`,
    entry.clientId === null ? "—" : `<span class="mono">${escapeHtml(entry.clientId)}</span>`,
    entry.detail === null ? "—" : escapeHtml(entry.detail),
  ])
  const content = `<section class="panel">
    <div class="panel__head"><div><h2 class="panel__title">${escapeHtml(i18n.t("Audit log"))}</h2><p class="panel__desc">${escapeHtml(i18n.t("Every security-relevant event, newest first."))}</p></div></div>
    <div class="panel__body">
      <form method="get" action="/console/audit" class="audit-filters">
        ${filterInput(i18n, "Event type", "event_type", filters.eventType)}
        ${filterInput(i18n, "User ID", "user_id", filters.userId)}
        ${filterInput(i18n, "Client ID", "client_id", filters.clientId)}
        ${filterInput(i18n, "Actor user ID", "actor_user_id", filters.actorUserId)}
        ${filterInput(i18n, "Actor client ID", "actor_client_id", filters.actorClientId)}
        <div class="audit-filters__actions">
          <button class="btn btn--primary btn--sm btn--auto" type="submit">${escapeHtml(i18n.t("Apply"))}</button>
          <a class="btn btn--ghost btn--sm btn--auto" href="/console/audit">${escapeHtml(i18n.t("Clear"))}</a>
        </div>
      </form>
    </div>
    ${dataTable(i18n, ["Time", "Event", "Result", "Actor user", "Actor client", "Subject user", "Subject client", "Detail"], rows, "No matching events.")}
    <div class="panel__body">${pager(i18n, baseHref(filters), limit, offset, logs.length, hasNext)}</div>
  </section>`
  return consoleShell(i18n.t("Audit log"), chrome, content)
}
