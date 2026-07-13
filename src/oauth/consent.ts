import { getConsent } from "../db/queries/consents"
import { parseScopeString } from "./scopes"

export async function consentCoversScopes(
  env: Env,
  userId: string,
  clientId: string,
  resource: string,
  requestedScopes: readonly string[],
): Promise<boolean> {
  const consent = await getConsent(env, userId, clientId, resource)
  if (consent === null) {
    return false
  }
  const granted = new Set(parseScopeString(consent.scope))
  return requestedScopes.every((scope) => granted.has(scope))
}
