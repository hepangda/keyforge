import { getUserPermissionRules } from "../db/queries/permission-group-rules"
import { yoloAllow } from "../operations/yolo"
import { isResourceAuthorizedScope, resolvePermissionRules } from "./permission-rules"

const ADMIN_SCOPES: ReadonlySet<string> = new Set(["admin.read", "admin.write"])

export type UserTokenAccessDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false
      readonly reason:
        | "application_resource"
        | "admin_scope"
        | "scope_denied"
        | "scope_not_allowed"
        | "invalid_policy"
    }

export type UserTokenAccessInput = {
  readonly userId: string
  readonly clientId: string
  readonly resourceUri: string
  readonly scopes: readonly string[]
}

/**
 * Evaluate the user's current permission-group rules for a user-backed token.
 * Base application/API rules are mandatory. Standard OIDC scopes inherit that
 * base decision; every custom scope additionally needs a matching allow rule.
 */
export async function evaluateUserTokenAccess(
  env: Env,
  input: UserTokenAccessInput,
): Promise<UserTokenAccessDecision> {
  if (yoloAllow(env, "user-token-policy")) return { allowed: true }

  const policy = await getUserPermissionRules(env, input.userId)
  if (!policy.valid) return { allowed: false, reason: "invalid_policy" }

  const uniqueScopes = [...new Set(input.scopes)]
  const context = {
    application: input.clientId,
    api: input.resourceUri,
    scope: uniqueScopes[0] ?? "",
  }
  const base = resolvePermissionRules(policy.rules, context, "base")
  if (!base.allowed) return { allowed: false, reason: "application_resource" }

  if (uniqueScopes.some((scope) => ADMIN_SCOPES.has(scope)) && !policy.adminMember) {
    return { allowed: false, reason: "admin_scope" }
  }

  for (const scope of uniqueScopes) {
    if (isResourceAuthorizedScope(scope)) continue
    const decision = resolvePermissionRules(policy.rules, { ...context, scope }, "scope")
    if (!decision.allowed) {
      return {
        allowed: false,
        reason: decision.reason === "denied" ? "scope_denied" : "scope_not_allowed",
      }
    }
  }
  return { allowed: true }
}
