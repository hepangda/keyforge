import { getConsent } from "../db/queries/consents"
import { yoloAllow } from "../operations/yolo"
import { parseScopeString } from "./scopes"

export async function consentCoversScopes(
  env: Env,
  userId: string,
  clientId: string,
  resource: string,
  requestedScopes: readonly string[],
): Promise<boolean> {
  // YOLO mode treats every request as already consented.
  if (yoloAllow(env, "consent")) return true
  const consent = await getConsent(env, userId, clientId, resource)
  if (consent === null) {
    return false
  }
  const granted = new Set(parseScopeString(consent.scope))
  return requestedScopes.every((scope) => granted.has(scope))
}
