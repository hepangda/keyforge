import { getResourceByUri } from "../db/queries/resources"
import { OAuthError } from "../security/errors"
import type { OAuthClient, OAuthResource } from "../types/domain"
import { validateRequestedScopes } from "./scopes"

/**
 * Resolve the access-token audience. Uses the request `resource` when present,
 * otherwise the client default. The result must be registered, enabled, and
 * within the client's allowed resources — every failure is a generic
 * invalid_target with an internal detail.
 */
export async function resolveResource(
  env: Env,
  client: OAuthClient,
  requestedResource: string | null,
): Promise<string> {
  return (await resolveResourceRecord(env, client, requestedResource)).resourceUri
}

async function resolveResourceRecord(
  env: Env,
  client: OAuthClient,
  requestedResource: string | null,
): Promise<OAuthResource> {
  const resource = requestedResource ?? client.defaultResource
  if (resource === null || resource === "") {
    throw new OAuthError("invalid_target", {
      description: "No target resource specified",
      detail: "request has no resource and client has no default_resource",
    })
  }
  if (!client.allowedResources.includes(resource)) {
    throw new OAuthError("invalid_target", {
      description: "The requested resource is not permitted",
      detail: `resource ${resource} not in client allowed_resources`,
    })
  }
  const registered = await getResourceByUri(env, resource)
  if (registered === null || !registered.enabled) {
    throw new OAuthError("invalid_target", {
      description: "Unknown or disabled resource",
      detail: `resource ${resource} not registered or disabled`,
    })
  }
  return registered
}

/**
 * Resolve a target resource and enforce the complete scope policy. A scope is
 * grantable only when both the client and the resource currently allow it.
 */
export async function resolveResourceForScopes(
  env: Env,
  client: OAuthClient,
  requestedResource: string | null,
  requestedScopes: readonly string[],
): Promise<string> {
  const registered = await resolveResourceRecord(env, client, requestedResource)
  const resource = registered.resourceUri
  validateRequestedScopes(requestedScopes, client.allowedScopes)
  try {
    validateRequestedScopes(requestedScopes, registered.allowedScopes)
  } catch (error) {
    if (error instanceof OAuthError && error.code === "invalid_scope") {
      throw new OAuthError("invalid_scope", {
        description: "One or more requested scopes are not permitted for this resource",
        detail: `resource ${resource} does not allow every requested scope`,
      })
    }
    throw error
  }
  return resource
}
