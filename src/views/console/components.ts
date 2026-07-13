import { escapeHtml } from "../layout"

export function fmtDate(epochSeconds: number): string {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(new Date(epochSeconds * 1000))
}

export function fmtDateTime(epochSeconds: number): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(epochSeconds * 1000))
}

export function csrfField(token: string): string {
  return `<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">`
}

export function dataTable(
  headers: readonly string[],
  rows: readonly (readonly string[])[],
  emptyMessage: string,
): string {
  if (rows.length === 0) {
    return `<div class="ctable-wrap"><div class="ctable__empty">${escapeHtml(emptyMessage)}</div></div>`
  }
  const head = headers.map((header) => `<th scope="col">${escapeHtml(header)}</th>`).join("")
  const body = rows
    .map(
      (cells) =>
        `<tr>${cells
          .map(
            (cell, index) =>
              `<td data-label="${escapeHtml(headers[index] ?? "")}"><div class="ctable__value">${cell}</div></td>`,
          )
          .join("")}</tr>`,
    )
    .join("")
  return `<div class="ctable-wrap"><table class="ctable"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`
}

export function statusBadge(ok: boolean, okLabel: string, offLabel: string): string {
  return ok
    ? `<span class="badge badge--ok"><span class="badge__dot"></span>${escapeHtml(okLabel)}</span>`
    : `<span class="badge badge--warn"><span class="badge__dot"></span>${escapeHtml(offLabel)}</span>`
}

export function scopeTags(values: readonly string[]): string {
  if (values.length === 0) {
    return `<span class="mono">—</span>`
  }
  return values.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")
}

export function pager(
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
      ? "<span>No results on this page.</span>"
      : `<span>Showing ${offset + 1}–${offset + rowCount}</span>`,
  ]
  if (offset > 0) {
    parts.push(
      `<a class="btn btn--ghost btn--tiny" href="${escapeHtml(pageHref(offset - limit))}">Previous</a>`,
    )
  }
  if (hasNext) {
    parts.push(
      `<a class="btn btn--ghost btn--tiny" href="${escapeHtml(pageHref(offset + limit))}">Next</a>`,
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

export function textField(label: string, name: string, value: string, opts?: FieldOptions): string {
  const type = opts?.type ?? "text"
  const req = opts?.required === true ? " required" : ""
  const ph = opts?.placeholder === undefined ? "" : ` placeholder="${escapeHtml(opts.placeholder)}"`
  const ro = opts?.readonly === true ? " readonly" : ""
  return `<label class="field"><span class="field__label">${escapeHtml(label)}</span><input class="input" type="${type}" name="${escapeHtml(name)}" value="${escapeHtml(value)}"${req}${ph}${ro}></label>`
}

export function textAreaField(label: string, name: string, value: string, hint?: string): string {
  const hintHtml = hint === undefined ? "" : `<p class="form-hint">${escapeHtml(hint)}</p>`
  return `<label class="field"><span class="field__label">${escapeHtml(label)}</span><textarea class="input" name="${escapeHtml(name)}" rows="3">${escapeHtml(value)}</textarea>${hintHtml}</label>`
}

export function checkboxField(label: string, name: string, checked: boolean): string {
  return `<label class="checkline"><input type="checkbox" name="${escapeHtml(name)}" value="1"${checked ? " checked" : ""}>${escapeHtml(label)}</label>`
}

export function selectField(
  label: string,
  name: string,
  options: readonly { readonly value: string; readonly label: string }[],
  selected: string,
): string {
  const opts = options
    .map(
      (option) =>
        `<option value="${escapeHtml(option.value)}"${option.value === selected ? " selected" : ""}>${escapeHtml(option.label)}</option>`,
    )
    .join("")
  return `<label class="field"><span class="field__label">${escapeHtml(label)}</span><select class="input" name="${escapeHtml(name)}">${opts}</select></label>`
}
