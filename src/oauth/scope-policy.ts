import { USER_ONLY_SCOPES } from "../config"

/**
 * Identity/session scopes are covered by the application and resource gates.
 * Permission-group scope rules only refine resource-specific capabilities.
 */
export const RESOURCE_AUTHORIZED_SCOPES = USER_ONLY_SCOPES

const RESOURCE_AUTHORIZED_SCOPE_SET: ReadonlySet<string> = new Set(RESOURCE_AUTHORIZED_SCOPES)

export function isPermissionGroupControlledScope(scope: string): boolean {
  return !RESOURCE_AUTHORIZED_SCOPE_SET.has(scope)
}
