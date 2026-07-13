import { DEVICE_CODE_GRANT, GRANT_TYPES, SUPPORTED_SCOPES, USER_ONLY_SCOPES } from "../config"
import { listResources } from "../db/queries/resources"
import type { ClientKind, ClientType } from "../types/domain"

export type ClientConfiguration = {
  readonly clientId: string
  readonly name: string
  readonly type: ClientType
  readonly clientKind: ClientKind
  readonly redirectUris: readonly string[]
  readonly postLogoutRedirectUris: readonly string[]
  readonly allowedScopes: readonly string[]
  readonly allowedGrantTypes: readonly string[]
  readonly allowedResources: readonly string[]
  readonly defaultResource: string | null
}

export type ClientConfigurationValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string }

function hasDuplicates(values: readonly string[]): boolean {
  return new Set(values).size !== values.length
}

/** Validate a client as one coherent, currently usable policy object. */
export async function validateClientConfiguration(
  env: Env,
  config: ClientConfiguration,
): Promise<ClientConfigurationValidation> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/.test(config.clientId)) {
    return { ok: false, reason: "client_id must be a URL-safe identifier of 1 to 128 characters" }
  }
  if (config.name.trim() === "" || config.name.length > 120) {
    return { ok: false, reason: "name must contain 1 to 120 characters" }
  }
  const lists = [
    config.redirectUris,
    config.postLogoutRedirectUris,
    config.allowedScopes,
    config.allowedGrantTypes,
    config.allowedResources,
  ]
  if (lists.some(hasDuplicates)) {
    return { ok: false, reason: "configuration lists must not contain duplicates" }
  }
  if (
    config.allowedScopes.length === 0 ||
    config.allowedScopes.some((scope) => !(SUPPORTED_SCOPES as readonly string[]).includes(scope))
  ) {
    return { ok: false, reason: "allowed_scopes contains an unknown scope or is empty" }
  }
  if (
    config.allowedGrantTypes.length === 0 ||
    config.allowedGrantTypes.some((grant) => !(GRANT_TYPES as readonly string[]).includes(grant))
  ) {
    return { ok: false, reason: "allowed_grant_types contains an unsupported grant" }
  }
  if (config.allowedResources.length === 0) {
    return { ok: false, reason: "at least one protected resource is required" }
  }
  if (
    config.defaultResource !== null &&
    !config.allowedResources.includes(config.defaultResource)
  ) {
    return { ok: false, reason: "default_resource must be one of allowed_resources" }
  }

  const resources = await listResources(env)
  const selected = resources.filter((resource) =>
    config.allowedResources.includes(resource.resourceUri),
  )
  if (
    selected.length !== config.allowedResources.length ||
    selected.some((resource) => !resource.enabled)
  ) {
    return { ok: false, reason: "every allowed resource must be registered and enabled" }
  }
  const resourceScopes = new Set(selected.flatMap((resource) => resource.allowedScopes))
  if (config.allowedScopes.some((scope) => !resourceScopes.has(scope))) {
    return { ok: false, reason: "one or more scopes are not offered by an allowed resource" }
  }

  const grants = new Set(config.allowedGrantTypes)
  if (config.type === "public" && grants.has("client_credentials")) {
    return { ok: false, reason: "public clients cannot use client_credentials" }
  }
  if (config.allowedScopes.includes("offline_access") && !grants.has("refresh_token")) {
    return { ok: false, reason: "offline_access requires the refresh_token grant" }
  }

  if (config.clientKind === "application") {
    if (
      !grants.has("authorization_code") ||
      [...grants].some((grant) => !["authorization_code", "refresh_token"].includes(grant)) ||
      config.redirectUris.length === 0
    ) {
      return {
        ok: false,
        reason:
          "application clients require authorization_code, redirects, and only optional refresh_token",
      }
    }
  } else if (config.clientKind === "device") {
    if (
      !grants.has(DEVICE_CODE_GRANT) ||
      [...grants].some((grant) => ![DEVICE_CODE_GRANT, "refresh_token"].includes(grant)) ||
      config.redirectUris.length !== 0 ||
      config.postLogoutRedirectUris.length !== 0
    ) {
      return {
        ok: false,
        reason: "device clients require device_code, no redirects, and only optional refresh_token",
      }
    }
  } else if (
    config.type !== "confidential" ||
    grants.size !== 1 ||
    !grants.has("client_credentials") ||
    config.redirectUris.length !== 0 ||
    config.postLogoutRedirectUris.length !== 0 ||
    config.allowedScopes.some((scope) => (USER_ONLY_SCOPES as readonly string[]).includes(scope))
  ) {
    return {
      ok: false,
      reason:
        "service clients must be confidential, use only client_credentials, and exclude user scopes and redirects",
    }
  }

  return { ok: true }
}
