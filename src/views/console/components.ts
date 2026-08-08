import type { I18n } from "../../i18n"
import { escapeHtml } from "../layout"

export function fmtDate(i18n: I18n, epochSeconds: number): string {
  return i18n.formatDate(epochSeconds)
}

export function fmtDateTime(i18n: I18n, epochSeconds: number): string {
  return i18n.formatDateTime(epochSeconds)
}

export function csrfField(token: string): string {
  return `<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">`
}

export function dataTable(
  i18n: I18n,
  headers: readonly string[],
  rows: readonly (readonly string[])[],
  emptyMessage: string,
): string {
  if (rows.length === 0) {
    return `<div class="ctable-wrap"><div class="ctable__empty">${escapeHtml(i18n.t(emptyMessage))}</div></div>`
  }
  const localizedHeaders = headers.map((header) => i18n.t(header))
  const head = localizedHeaders
    .map((header) => `<th scope="col">${escapeHtml(header)}</th>`)
    .join("")
  const body = rows
    .map(
      (cells) =>
        `<tr>${cells
          .map(
            (cell, index) =>
              `<td data-label="${escapeHtml(localizedHeaders[index] ?? "")}"><div class="ctable__value">${cell}</div></td>`,
          )
          .join("")}</tr>`,
    )
    .join("")
  return `<div class="ctable-wrap"><table class="ctable"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`
}

export function statusBadge(i18n: I18n, ok: boolean, okLabel: string, offLabel: string): string {
  return ok
    ? `<span class="badge badge--ok"><span class="badge__dot"></span>${escapeHtml(i18n.t(okLabel))}</span>`
    : `<span class="badge badge--warn"><span class="badge__dot"></span>${escapeHtml(i18n.t(offLabel))}</span>`
}

export function scopeTags(values: readonly string[]): string {
  if (values.length === 0) {
    return `<span class="mono">—</span>`
  }
  return values.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")
}
export function secondaryTabs(
  i18n: I18n,
  ariaLabel: string,
  tabs: readonly { readonly label: string; readonly href: string; readonly active: boolean }[],
): string {
  const links = tabs
    .map((tab) => {
      const active = tab.active ? " subtab--active" : ""
      const current = tab.active ? ' aria-current="page"' : ""
      return `<a class="subtab${active}" href="${escapeHtml(tab.href)}"${current}>${escapeHtml(i18n.t(tab.label))}</a>`
    })
    .join("")
  return `<nav class="subtabs" aria-label="${escapeHtml(i18n.t(ariaLabel))}">${links}</nav>`
}
export function consoleEntityLink(kind: "user" | "client" | "resource", value: string): string {
  const href =
    kind === "user"
      ? `/console/users/${encodeURIComponent(value)}`
      : kind === "client"
        ? `/console/clients/${encodeURIComponent(value)}`
        : `/console/resources/${encodeURIComponent(value)}`
  return `<a class="mono" href="${escapeHtml(href)}">${escapeHtml(value)}</a>`
}

export function pager(
  i18n: I18n,
  baseHref: string,
  limit: number,
  offset: number,
  rowCount: number,
  hasNext: boolean,
): string {
  if (rowCount === 0 && offset === 0) {
    return ""
  }
  const sep = baseHref.includes("?") ? "&" : "?"
  const pageHref = (nextOffset: number) =>
    `${baseHref}${sep}limit=${limit}&offset=${Math.max(nextOffset, 0)}`
  const parts: string[] = [
    rowCount === 0
      ? `<span>${escapeHtml(i18n.t("No results on this page."))}</span>`
      : `<span>${escapeHtml(i18n.t("Showing {start}–{end}", { start: offset + 1, end: offset + rowCount }))}</span>`,
  ]
  if (offset > 0) {
    parts.push(
      `<a class="btn btn--ghost btn--tiny" href="${escapeHtml(pageHref(offset - limit))}">${escapeHtml(i18n.t("Previous"))}</a>`,
    )
  }
  if (hasNext) {
    parts.push(
      `<a class="btn btn--ghost btn--tiny" href="${escapeHtml(pageHref(offset + limit))}">${escapeHtml(i18n.t("Next"))}</a>`,
    )
  }
  return `<div class="pager">${parts.join("")}</div>`
}

export type FieldOptions = {
  readonly type?: string
  readonly required?: boolean
  readonly placeholder?: string
  readonly readonly?: boolean
  readonly wide?: boolean
  readonly error?: string | undefined
}

export function textField(
  i18n: I18n,
  label: string,
  name: string,
  value: string,
  opts?: FieldOptions,
): string {
  const type = opts?.type ?? "text"
  const req = opts?.required === true ? " required" : ""
  const ph =
    opts?.placeholder === undefined ? "" : ` placeholder="${escapeHtml(i18n.t(opts.placeholder))}"`
  const ro = opts?.readonly === true ? " readonly" : ""
  const fieldId = `${name}-field`
  const errorId = `${name}-error`
  const invalid = opts?.error === undefined ? "" : ' aria-invalid="true"'
  const describedBy = opts?.error === undefined ? "" : ` aria-describedby="${escapeHtml(errorId)}"`
  const wide = opts?.wide === true ? " field--wide" : ""
  const errorHtml =
    opts?.error === undefined
      ? ""
      : `<span class="field__error" id="${escapeHtml(errorId)}">${escapeHtml(i18n.t(opts.error))}</span>`
  return `<label class="field${wide}" id="${escapeHtml(fieldId)}"><span class="field__label">${escapeHtml(i18n.t(label))}</span><input class="input" type="${type}" name="${escapeHtml(name)}" value="${escapeHtml(value)}"${req}${ph}${ro}${invalid}${describedBy}>${errorHtml}</label>`
}

export function textAreaField(
  i18n: I18n,
  label: string,
  name: string,
  value: string,
  hint?: string,
  opts?: FieldOptions,
): string {
  const hintHtml = hint === undefined ? "" : `<p class="form-hint">${escapeHtml(i18n.t(hint))}</p>`
  const required = opts?.required === true ? " required" : ""
  const fieldId = `${name}-field`
  const errorId = `${name}-error`
  const invalid = opts?.error === undefined ? "" : ' aria-invalid="true"'
  const describedBy = opts?.error === undefined ? "" : ` aria-describedby="${escapeHtml(errorId)}"`
  const wide = opts?.wide === true ? " field--wide" : ""
  const errorHtml =
    opts?.error === undefined
      ? ""
      : `<span class="field__error" id="${escapeHtml(errorId)}">${escapeHtml(i18n.t(opts.error))}</span>`
  return `<label class="field${wide}" id="${escapeHtml(fieldId)}"><span class="field__label">${escapeHtml(i18n.t(label))}</span><textarea class="input" name="${escapeHtml(name)}" rows="3"${required}${invalid}${describedBy}>${escapeHtml(value)}</textarea>${errorHtml}${hintHtml}</label>`
}

export function checkboxField(i18n: I18n, label: string, name: string, checked: boolean): string {
  return `<label class="checkline"><input type="checkbox" name="${escapeHtml(name)}" value="1"${checked ? " checked" : ""}>${escapeHtml(i18n.t(label))}</label>`
}
