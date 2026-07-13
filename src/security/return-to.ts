/**
 * Prevent open redirects: accept only a URL-path that remains same-origin
 * after browser URL parsing. Backslashes are rejected because browsers treat
 * them as path separators for special schemes (`/\\evil.test` -> `//evil.test`).
 */
export function safeLocalPath(raw: string | null): string {
  if (
    raw === null ||
    !raw.startsWith("/") ||
    raw.startsWith("//") ||
    raw.includes("\\") ||
    [...raw].some((character) => {
      const code = character.charCodeAt(0)
      return code <= 31 || code === 127
    })
  ) {
    return "/"
  }
  try {
    const base = new URL("https://keyforge.invalid/")
    const parsed = new URL(raw, base)
    return parsed.origin === base.origin ? `${parsed.pathname}${parsed.search}${parsed.hash}` : "/"
  } catch {
    return "/"
  }
}
