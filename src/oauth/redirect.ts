import type { OAuthClient } from "../types/domain"

/** Exact-match check — no wildcards, no prefix matching, no normalization. */
export function isRegisteredRedirectUri(client: OAuthClient, redirectUri: string): boolean {
  return client.redirectUris.includes(redirectUri)
}

export function buildRedirectUrl(redirectUri: string, params: Record<string, string>): string {
  const url = new URL(redirectUri)
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value)
  }
  return url.toString()
}
