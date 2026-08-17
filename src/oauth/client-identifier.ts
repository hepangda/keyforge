/** Maximum UTF-8 length of an HTTPS Client Identifier URL. */
export const CLIENT_IDENTIFIER_URL_MAX_BYTES = 2048

/** Locally managed client IDs remain compact, URL-safe identifiers. */
export const STATIC_CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/

/** Parse the strict URL form defined by OAuth Client ID Metadata Documents. */
export function parseClientIdentifierUrl(raw: string): URL | null {
  if (new TextEncoder().encode(raw).byteLength > CLIENT_IDENTIFIER_URL_MAX_BYTES) return null
  if (raw.includes("?") || raw.includes("#") || /(?:\*|%2a)/i.test(raw)) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (
    url.protocol !== "https:" ||
    url.hostname === "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.pathname === "" ||
    url.pathname === "/" ||
    url.search !== ""
  ) {
    return null
  }
  const pathSegments = url.pathname.split("/")
  if (pathSegments.some((segment) => segment === "." || segment === "..")) return null
  // URL normalisation can hide an encoded dot segment. Compare against the
  // original path so those inputs cannot be silently accepted.
  const rawWithoutQueryOrFragment = raw.slice(
    0,
    raw.search(/[?#]/) === -1 ? raw.length : raw.search(/[?#]/),
  )
  const rawPathStart = rawWithoutQueryOrFragment.indexOf("/", "https://".length)
  const rawPath = rawPathStart === -1 ? "" : rawWithoutQueryOrFragment.slice(rawPathStart)
  if (/(?:^|\/)(?:\.|%2e){1,2}(?:\/|$)/i.test(rawPath)) return null
  return url
}

export function isValidOAuthClientId(raw: string): boolean {
  return STATIC_CLIENT_ID_PATTERN.test(raw) || parseClientIdentifierUrl(raw) !== null
}
