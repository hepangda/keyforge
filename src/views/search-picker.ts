import type { I18n } from "../i18n"
import { escapeHtml } from "./layout"

export type SearchPickerOption = {
  readonly value: string
  readonly title: string
  readonly detail?: string
  readonly meta?: string
  readonly keywords?: string
  readonly selected?: boolean
  readonly recommended?: boolean
  readonly disabled?: boolean
  readonly data?: Readonly<Record<string, string>>
}

export type SearchPickerConfig = {
  readonly id: string
  readonly name: string
  readonly label: string
  readonly placeholder: string
  readonly selectedLabel?: string
  readonly emptySelection?: string
  readonly emptyResults?: string
  readonly recommendedLabel?: string
  readonly resultsLabel?: string
  readonly requiredMessage?: string
  readonly maxSelections?: number
  readonly required?: boolean
}

function optionDataAttributes(data: Readonly<Record<string, string>> | undefined): string {
  if (data === undefined) return ""
  return Object.entries(data)
    .filter(([key]) => /^[a-z0-9-]+$/.test(key))
    .map(([key, value]) => ` data-${key}="${escapeHtml(value)}"`)
    .join("")
}

export function searchPicker(
  i18n: I18n,
  config: SearchPickerConfig,
  options: readonly SearchPickerOption[],
): string {
  const selectedLabel = config.selectedLabel ?? "Selected"
  const emptySelection = config.emptySelection ?? "Nothing selected yet."
  const emptyResults = config.emptyResults ?? "No matches found."
  const recommendedLabel = config.recommendedLabel ?? "Recommended"
  const resultsLabel = config.resultsLabel ?? "Search results"
  const requiredMessage = config.requiredMessage ?? "Choose at least one item."
  const maxSelections = config.maxSelections ?? 0
  const selectId = `${config.id}-select`
  const queryId = `${config.id}-query`
  const resultsId = `${config.id}-results`
  const optionHtml = options
    .map((option) => {
      const searchText = [
        option.title,
        option.detail ?? "",
        option.meta ?? "",
        option.keywords ?? "",
        option.value,
      ].join(" ")
      return `<option value="${escapeHtml(option.value)}" data-title="${escapeHtml(option.title)}" data-detail="${escapeHtml(option.detail ?? "")}" data-meta="${escapeHtml(option.meta ?? "")}" data-search="${escapeHtml(searchText)}"${option.recommended === true ? ' data-recommended="1"' : ""}${optionDataAttributes(option.data)}${option.selected === true ? " selected" : ""}${option.disabled === true ? " disabled" : ""}>${escapeHtml(option.title)}${option.meta === undefined ? "" : ` — ${escapeHtml(option.meta)}`}</option>`
    })
    .join("")
  const required = config.required === true ? " required" : ""
  return `<div class="search-picker" data-search-picker data-max-selections="${maxSelections}" data-recommended-label="${escapeHtml(i18n.t(recommendedLabel))}" data-results-label="${escapeHtml(i18n.t(resultsLabel))}" data-empty-results="${escapeHtml(i18n.t(emptyResults))}" data-add-label="${escapeHtml(i18n.t("Add"))}" data-remove-label="${escapeHtml(i18n.t("Remove"))}" data-count-label="${escapeHtml(i18n.t("{count} selected"))}" data-required-message="${escapeHtml(i18n.t(requiredMessage))}">
    <label class="field search-picker__native-field" for="${escapeHtml(selectId)}"><span class="field__label">${escapeHtml(i18n.t(config.label))}</span><select class="input search-picker__native" id="${escapeHtml(selectId)}" name="${escapeHtml(config.name)}" multiple size="6"${required}>${optionHtml}</select></label>
    <div class="search-picker__enhanced">
      <label class="field search-picker__query-field" for="${escapeHtml(queryId)}"><span class="field__label">${escapeHtml(i18n.t(config.label))}</span><input class="input" id="${escapeHtml(queryId)}" type="search" autocomplete="off" placeholder="${escapeHtml(i18n.t(config.placeholder))}" role="combobox" aria-autocomplete="list" aria-controls="${escapeHtml(resultsId)}" data-search-picker-query></label>
      <div class="search-picker__workbench">
        <section class="search-picker__well" aria-labelledby="${escapeHtml(config.id)}-results-label">
          <div class="search-picker__well-head"><span id="${escapeHtml(config.id)}-results-label" data-search-picker-results-label>${escapeHtml(i18n.t(recommendedLabel))}</span><span data-search-picker-results-count></span></div>
          <div class="search-picker__options" id="${escapeHtml(resultsId)}" role="listbox" data-search-picker-results></div>
          <p class="search-picker__empty" data-search-picker-results-empty hidden>${escapeHtml(i18n.t(emptyResults))}</p>
        </section>
        <section class="search-picker__well search-picker__well--selected" aria-labelledby="${escapeHtml(config.id)}-selected-label">
          <div class="search-picker__well-head"><span id="${escapeHtml(config.id)}-selected-label">${escapeHtml(i18n.t(selectedLabel))}</span><span data-search-picker-selected-count></span></div>
          <div class="search-picker__selections" data-search-picker-selected></div>
          <p class="search-picker__empty" data-search-picker-selected-empty>${escapeHtml(i18n.t(emptySelection))}</p>
        </section>
      </div>
    </div>
  </div>`
}
