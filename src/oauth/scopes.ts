import { OAuthError } from "../security/errors"

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
