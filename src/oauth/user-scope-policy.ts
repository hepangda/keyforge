import { getUserGroupNames } from "../db/queries/users"

const ADMIN_GROUP = "admins"
const ADMIN_SCOPES = new Set(["admin.read", "admin.write"])

/** Enforce workforce authorization before privileged user scopes are issued. */
export async function userMayReceiveScopes(
  env: Env,
  userId: string,
  scopes: readonly string[],
): Promise<boolean> {
  if (!scopes.some((scope) => ADMIN_SCOPES.has(scope))) {
    return true
  }
  return (await getUserGroupNames(env, userId)).includes(ADMIN_GROUP)
}
