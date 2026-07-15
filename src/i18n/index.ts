import { MESSAGE_CATALOG } from "./catalog"

export const SUPPORTED_LOCALES = ["en", "zh-CN", "ja"] as const
export type Locale = (typeof SUPPORTED_LOCALES)[number]
export type NonEnglishLocale = Exclude<Locale, "en">
export type LanguagePreference = Locale | "auto"
export type LocaleSource = "preference" | "environment" | "default"
export type MessageValues = Readonly<Record<string, string | number>>

export type I18n = {
  readonly locale: Locale
  readonly preference: LanguagePreference
  readonly source: LocaleSource
  readonly returnTo: string
  readonly t: (message: string, values?: MessageValues) => string
  readonly formatDate: (epochSeconds: number) => string
  readonly formatDateTime: (epochSeconds: number) => string
}

export type ResolvedLocale = {
  readonly locale: Locale
  readonly preference: LanguagePreference
  readonly source: LocaleSource
}

const DATE_LOCALES: Readonly<Record<Locale, string>> = {
  en: "en-US",
  "zh-CN": "zh-CN",
  ja: "ja-JP",
}

export function isLocale(value: string | undefined): value is Locale {
  return SUPPORTED_LOCALES.some((locale) => locale === value)
}

function localeForLanguageTag(tag: string): Locale | undefined {
  const normalized = tag.trim().toLowerCase()
  if (normalized === "zh" || normalized.startsWith("zh-")) return "zh-CN"
  if (normalized === "ja" || normalized.startsWith("ja-")) return "ja"
  if (normalized === "en" || normalized.startsWith("en-")) return "en"
  return undefined
}

/** Resolve a browser Accept-Language header using quality weights and order. */
export function localeFromAcceptLanguage(header: string | undefined): Locale | undefined {
  if (header === undefined || header.trim() === "") return undefined
  const candidates = header
    .split(",")
    .map((part, index) => {
      const [rawTag = "", ...parameters] = part.trim().split(";")
      let quality = 1
      for (const parameter of parameters) {
        if (/^\s*q\s*=/i.test(parameter)) {
          const match = /^\s*q\s*=\s*(0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\s*$/i.exec(parameter)
          quality = match === null ? 0 : Number(match[1])
        }
      }
      return { tag: rawTag, quality, index }
    })
    .filter((candidate) => candidate.quality > 0)
    .sort((left, right) => right.quality - left.quality || left.index - right.index)

  for (const candidate of candidates) {
    if (candidate.tag.trim() === "*") return "en"
    const locale = localeForLanguageTag(candidate.tag)
    if (locale !== undefined) return locale
  }
  return undefined
}

export function resolveLocale(
  savedPreference: string | undefined,
  acceptLanguage: string | undefined,
): ResolvedLocale {
  if (isLocale(savedPreference)) {
    return { locale: savedPreference, preference: savedPreference, source: "preference" }
  }
  const environmentLocale = localeFromAcceptLanguage(acceptLanguage)
  return environmentLocale === undefined
    ? { locale: "en", preference: "auto", source: "default" }
    : { locale: environmentLocale, preference: "auto", source: "environment" }
}

function interpolate(message: string, values: MessageValues | undefined): string {
  if (values === undefined) return message
  return message.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (placeholder, name: string) => {
    const value = values[name]
    return value === undefined ? placeholder : String(value)
  })
}

export function translate(locale: Locale, message: string, values?: MessageValues): string {
  if (locale === "en") return interpolate(message, values)
  const localized = (MESSAGE_CATALOG as Readonly<Record<string, Record<NonEnglishLocale, string>>>)[
    message
  ]?.[locale]
  return interpolate(localized ?? message, values)
}

export function createI18n(resolved: ResolvedLocale, returnTo = "/"): I18n {
  const dateLocale = DATE_LOCALES[resolved.locale]
  return {
    ...resolved,
    returnTo,
    t: (message, values) => translate(resolved.locale, message, values),
    formatDate: (epochSeconds) =>
      new Intl.DateTimeFormat(dateLocale, {
        year: "numeric",
        month: "short",
        day: "numeric",
      }).format(new Date(epochSeconds * 1000)),
    formatDateTime: (epochSeconds) =>
      new Intl.DateTimeFormat(dateLocale, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(new Date(epochSeconds * 1000)),
  }
}

export const DEFAULT_I18N = createI18n({
  locale: "en",
  preference: "auto",
  source: "default",
})
