import { isMetadataClientApproved } from "../db/queries/clients"
import { getResourceByUri } from "../db/queries/resources"
import { isYoloEnabled } from "../operations/yolo"
import { OAuthError } from "../security/errors"
import { isMcpResourceUriAllowed } from "../security/redirect-uri"
import { asResourceUri, type OAuthClient, type OAuthResource } from "../types/domain"
import { isPermissionGroupControlledScope } from "./scope-policy"
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
  const yolo = isYoloEnabled(env)
  const resource = requestedResource ?? client.defaultResource
  if (resource === null || resource === "") {
    throw new OAuthError("invalid_target", {
      description: "No target resource specified",
      detail: "request has no resource and client has no default_resource",
    })
  }
  if (!yolo && !client.allowedResources.includes(resource)) {
    throw new OAuthError("invalid_target", {
      description: "The requested resource is not permitted",
      detail: `resource ${resource} not in client allowed_resources`,
    })
  }
  const registered = await getResourceByUri(env, resource)
  if (registered === null || !registered.enabled) {
    // YOLO mode synthesizes an unregistered resource rather than failing, so a
    // dev client can point at any audience it likes.
    if (yolo) {
      return {
        resourceUri: asResourceUri(resource),
        name: registered?.name ?? resource,
        allowedScopes: registered?.allowedScopes ?? client.allowedScopes,
        enabled: true,
        mcpEnabled: registered?.mcpEnabled ?? false,
        metadataClientPolicy: registered?.metadataClientPolicy ?? "disabled",
      }
    }
    throw new OAuthError("invalid_target", {
      description: "Unknown or disabled resource",
      detail: `resource ${resource} not registered or disabled`,
    })
  }
  if (registered.mcpEnabled && !isMcpResourceUriAllowed(env.ENVIRONMENT, registered.resourceUri)) {
    throw new OAuthError("invalid_target", {
      description: "The requested resource is not available in this environment",
      detail: `resource ${resource} violates the ${env.ENVIRONMENT ?? "unknown"} transport policy`,
    })
  }
  if (!yolo && registered.mcpEnabled && requestedResource === null) {
    throw new OAuthError("invalid_target", {
      description: "The resource parameter is required for this protected resource",
      detail: `MCP resource ${resource} was selected only through client default_resource`,
    })
  }
  if (!yolo && client.registrationType === "client_id_metadata") {
    const approved =
      registered.metadataClientPolicy === "admin_approved" &&
      (await isMetadataClientApproved(env, client.clientId, registered.resourceUri))
    if (
      !registered.mcpEnabled ||
      registered.metadataClientPolicy === "disabled" ||
      (registered.metadataClientPolicy === "admin_approved" && !approved)
    ) {
      throw new OAuthError("invalid_target", {
        description: "The requested resource does not admit this client",
        detail: `metadata client ${client.clientId} is not admitted to resource ${resource}`,
      })
    }
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
  // YOLO mode grants every requested scope regardless of client or resource policy.
  if (isYoloEnabled(env)) return resource
  validateRequestedScopes(requestedScopes, client.allowedScopes)
  const resourceSpecificScopes = requestedScopes.filter(isPermissionGroupControlledScope)
  try {
    validateRequestedScopes(resourceSpecificScopes, registered.allowedScopes)
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
