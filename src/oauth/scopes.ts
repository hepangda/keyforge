import { OAuthError } from "../security/errors"

export const OAUTH_SCOPE_MAX_COUNT = 64
export const OAUTH_SCOPE_MAX_BYTES = 128
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/
const encoder = new TextEncoder()

export type ScopeCatalogValidation =
  | { readonly ok: true; readonly scopes: readonly string[] }
  | { readonly ok: false; readonly reason: "too_many" | "duplicate" | "invalid" }

/** Validate RFC 6749 scope-token syntax and operational size bounds. */
export function validateScopeCatalog(scopes: readonly string[]): ScopeCatalogValidation {
  if (scopes.length > OAUTH_SCOPE_MAX_COUNT) return { ok: false, reason: "too_many" }
  if (new Set(scopes).size !== scopes.length) return { ok: false, reason: "duplicate" }
  if (
    scopes.some(
      (scope) =>
        !SCOPE_TOKEN.test(scope) ||
        encoder.encode(scope).byteLength === 0 ||
        encoder.encode(scope).byteLength > OAUTH_SCOPE_MAX_BYTES,
    )
  ) {
    return { ok: false, reason: "invalid" }
  }
  return { ok: true, scopes: [...scopes] }
}

export function parseScopeString(raw: string | null | undefined): string[] {
  if (raw === null || raw === undefined) {
    return []
  }
  return raw
    .trim()
    .split(/\s+/)
    .filter((scope) => scope.length > 0)
}

export function serializeScopes(scopes: readonly string[]): string {
  return scopes.join(" ")
}

/** Return the requested scopes if every one is within `allowed`; else throw invalid_scope. */
export function validateRequestedScopes(
  requested: readonly string[],
  allowed: readonly string[],
): string[] {
  const allowedSet = new Set(allowed)
  const disallowed = requested.filter((scope) => !allowedSet.has(scope))
  if (disallowed.length > 0) {
    throw new OAuthError("invalid_scope", {
      description: "One or more requested scopes are not permitted",
      detail: `disallowed scopes: ${disallowed.join(" ")}`,
    })
  }
  return [...requested]
}
