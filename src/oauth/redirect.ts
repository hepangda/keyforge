import type { OAuthClient } from "../types/domain"

function isLoopbackIpRedirectUri(raw: string): URL | null {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== "http:") return null
  return url.hostname === "127.0.0.1" || url.hostname === "[::1]" ? url : null
}

function matchesLoopbackRedirectExceptPort(registered: string, presented: string): boolean {
  const registeredUrl = isLoopbackIpRedirectUri(registered)
  const presentedUrl = isLoopbackIpRedirectUri(presented)
  if (registeredUrl === null || presentedUrl === null) return false
  return (
    registeredUrl.hostname === presentedUrl.hostname &&
    registeredUrl.username === presentedUrl.username &&
    registeredUrl.password === presentedUrl.password &&
    registeredUrl.pathname === presentedUrl.pathname &&
    registeredUrl.search === presentedUrl.search &&
    registeredUrl.hash === presentedUrl.hash
  )
}

/**
 * Exact-match check, except that CIMD native clients may select an ephemeral
 * port for an otherwise identical loopback IP redirect URI (RFC 8252 §7.3).
 */
export function isRegisteredRedirectUri(client: OAuthClient, redirectUri: string): boolean {
  if (client.redirectUris.includes(redirectUri)) return true
  return (
    client.registrationType === "client_id_metadata" &&
    client.redirectUris.some((registered) =>
      matchesLoopbackRedirectExceptPort(registered, redirectUri),
    )
  )
}

/** CSP source expression for a redirect URI already proven to be registered. */
export function formActionSource(redirectUri: string): string {
  const url = new URL(redirectUri)
  return url.origin === "null" ? url.protocol : url.origin
}

export function buildRedirectUrl(redirectUri: string, params: Record<string, string>): string {
  const url = new URL(redirectUri)
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value)
  }
  return url.toString()
}
