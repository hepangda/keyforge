import { getUserGroupNames } from "../db/queries/users"
import { yoloAllow } from "../operations/yolo"

const ADMIN_GROUP = "admins"
const ADMIN_SCOPES = new Set(["admin.read", "admin.write"])

/** Enforce workforce authorization before privileged user scopes are issued. */
export async function userMayReceiveScopes(
  env: Env,
  userId: string,
  scopes: readonly string[],
): Promise<boolean> {
  if (yoloAllow(env, "user-scope-policy")) return true
  if (!scopes.some((scope) => ADMIN_SCOPES.has(scope))) {
    return true
  }
  return (await getUserGroupNames(env, userId)).includes(ADMIN_GROUP)
}
