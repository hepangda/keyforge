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
  return `<label class="field"><span class="field__label">${escapeHtml(i18n.t(label))}</span><input class="input" type="${type}" name="${escapeHtml(name)}" value="${escapeHtml(value)}"${req}${ph}${ro}></label>`
}

export function textAreaField(
  i18n: I18n,
  label: string,
  name: string,
  value: string,
  hint?: string,
  opts?: { readonly required?: boolean },
): string {
  const hintHtml = hint === undefined ? "" : `<p class="form-hint">${escapeHtml(i18n.t(hint))}</p>`
  const required = opts?.required === true ? " required" : ""
  return `<label class="field"><span class="field__label">${escapeHtml(i18n.t(label))}</span><textarea class="input" name="${escapeHtml(name)}" rows="3"${required}>${escapeHtml(value)}</textarea>${hintHtml}</label>`
}

export function checkboxField(i18n: I18n, label: string, name: string, checked: boolean): string {
  return `<label class="checkline"><input type="checkbox" name="${escapeHtml(name)}" value="1"${checked ? " checked" : ""}>${escapeHtml(i18n.t(label))}</label>`
}

export function selectField(
  i18n: I18n,
  label: string,
  name: string,
  options: readonly { readonly value: string; readonly label: string }[],
  selected: string,
): string {
  const opts = options
    .map(
      (option) =>
        `<option value="${escapeHtml(option.value)}"${option.value === selected ? " selected" : ""}>${escapeHtml(i18n.t(option.label))}</option>`,
    )
    .join("")
  return `<label class="field"><span class="field__label">${escapeHtml(i18n.t(label))}</span><select class="input" name="${escapeHtml(name)}">${opts}</select></label>`
}
