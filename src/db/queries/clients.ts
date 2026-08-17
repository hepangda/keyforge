import * as z from "zod"
import type {
  ClientKind,
  ClientType,
  OAuthClient,
  TokenEndpointAuthMethod,
} from "../../types/domain"
import { asClientId } from "../../types/domain"
import { nowSeconds } from "../../utils/time"

const clientRowSchema = z.object({
  client_id: z.string(),
  name: z.string(),
  client_secret_hash: z.string().nullable(),
  type: z.enum(["public", "confidential"]),
  client_kind: z.enum(["application", "device", "service"]),
  redirect_uris_json: z.string(),
  post_logout_redirect_uris_json: z.string(),
  allowed_scopes_json: z.string(),
  allowed_grant_types_json: z.string(),
  allowed_resources_json: z.string(),
  default_resource: z.string().nullable(),
  require_pkce: z.number(),
  enabled: z.number(),
  registration_type: z.enum(["static", "client_id_metadata"]),
  metadata_expires_at: z.number().nullable(),
  metadata_fingerprint: z.string().nullable(),
  token_endpoint_auth_methods_json: z.string(),
  metadata_jwks_uri: z.string().nullable(),
  introspection_allowed: z.number(),
})

const stringArraySchema = z.array(z.string())
const tokenEndpointAuthMethodsSchema = z.array(
  z.enum(["client_secret_basic", "client_secret_post", "none", "private_key_jwt"]),
)

function parseJsonStringArray(raw: string): string[] {
  const result = stringArraySchema.safeParse(JSON.parse(raw))
  return result.success ? result.data : []
}

const CLIENT_COLUMNS = `client_id, name, client_secret_hash, type, client_kind, redirect_uris_json,
  post_logout_redirect_uris_json,
  allowed_scopes_json, allowed_grant_types_json, allowed_resources_json,
  default_resource, require_pkce, enabled, registration_type, metadata_expires_at,
  metadata_fingerprint, token_endpoint_auth_methods_json, metadata_jwks_uri,
  introspection_allowed`

function mapClient(row: unknown): OAuthClient {
  const parsed = clientRowSchema.parse(row)
  return {
    clientId: asClientId(parsed.client_id),
    name: parsed.name,
    type: parsed.type,
    clientKind: parsed.client_kind,
    clientSecretHash: parsed.client_secret_hash,
    redirectUris: parseJsonStringArray(parsed.redirect_uris_json),
    postLogoutRedirectUris: parseJsonStringArray(parsed.post_logout_redirect_uris_json),
    allowedScopes: parseJsonStringArray(parsed.allowed_scopes_json),
    allowedGrantTypes: parseJsonStringArray(parsed.allowed_grant_types_json),
    allowedResources: parseJsonStringArray(parsed.allowed_resources_json),
    defaultResource: parsed.default_resource,
    // OAuth 2.1 policy is uniform: every authorization-code request uses S256.
    // Keep parsing the legacy column for migration compatibility, but never
    // expose a per-client downgrade switch.
    requirePkce: true,
    tokenEndpointAuthMethods: tokenEndpointAuthMethodsSchema.parse(
      JSON.parse(parsed.token_endpoint_auth_methods_json),
    ),
    introspectionAllowed: parsed.introspection_allowed === 1,
    enabled: parsed.enabled === 1,
    registrationType: parsed.registration_type,
    metadataFingerprint: parsed.metadata_fingerprint,
    metadataExpiresAt: parsed.metadata_expires_at,
    metadataJwksUri: parsed.metadata_jwks_uri,
  }
}

export async function getClientById(env: Env, clientId: string): Promise<OAuthClient | null> {
  const row = await env.DB.prepare(
    `SELECT ${CLIENT_COLUMNS} FROM oauth_clients WHERE client_id = ?`,
  )
    .bind(clientId)
    .first()
  return row === null ? null : mapClient(row)
}

export async function listClients(env: Env): Promise<OAuthClient[]> {
  const result = await env.DB.prepare(
    `SELECT ${CLIENT_COLUMNS} FROM oauth_clients ORDER BY created_at DESC`,
  ).all()
  return result.results.map(mapClient)
}

export async function listClientsPaginated(
  env: Env,
  limit: number,
  offset: number,
): Promise<OAuthClient[]> {
  const result = await env.DB.prepare(
    `SELECT ${CLIENT_COLUMNS} FROM oauth_clients ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(limit, offset)
    .all()
  return result.results.map(mapClient)
}

export type CreateClientInput = {
  readonly clientId: string
  readonly name: string
  readonly type: ClientType
  readonly clientKind: ClientKind
  readonly redirectUris: readonly string[]
  readonly postLogoutRedirectUris?: readonly string[]
  readonly allowedScopes: readonly string[]
  readonly allowedGrantTypes: readonly string[]
  readonly allowedResources: readonly string[]
  readonly defaultResource: string | null
  readonly requirePkce: boolean
  readonly introspectionAllowed?: boolean
}

export async function createClient(
  env: Env,
  input: CreateClientInput,
  secretHash: string | null,
): Promise<void> {
  const now = nowSeconds()
  await env.DB.prepare(
    `INSERT INTO oauth_clients
       (client_id, name, client_secret_hash, type, client_kind, redirect_uris_json,
        post_logout_redirect_uris_json,
        allowed_scopes_json, allowed_grant_types_json, allowed_resources_json,
        default_resource, require_pkce, enabled, token_endpoint_auth_methods_json,
        introspection_allowed, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
  )
    .bind(
      input.clientId,
      input.name,
      secretHash,
      input.type,
      input.clientKind,
      JSON.stringify(input.redirectUris),
      JSON.stringify(input.postLogoutRedirectUris ?? []),
      JSON.stringify(input.allowedScopes),
      JSON.stringify(input.allowedGrantTypes),
      JSON.stringify(input.allowedResources),
      input.defaultResource,
      1,
      JSON.stringify(
        input.type === "public"
          ? (["none"] satisfies readonly TokenEndpointAuthMethod[])
          : ([
              "client_secret_basic",
              "client_secret_post",
            ] satisfies readonly TokenEndpointAuthMethod[]),
      ),
      input.introspectionAllowed === true ? 1 : 0,
      now,
      now,
    )
    .run()
}

export type ClientPatch = {
  readonly name?: string
  readonly redirectUris?: readonly string[]
  readonly postLogoutRedirectUris?: readonly string[]
  readonly allowedScopes?: readonly string[]
  readonly allowedGrantTypes?: readonly string[]
  readonly allowedResources?: readonly string[]
  readonly defaultResource?: string | null
  readonly requirePkce?: boolean
  readonly introspectionAllowed?: boolean
}

export async function updateClient(env: Env, id: string, patch: ClientPatch): Promise<boolean> {
  const current = await getClientById(env, id)
  if (current === null) {
    return false
  }
  const next = {
    name: patch.name ?? current.name,
    redirectUris: patch.redirectUris ?? current.redirectUris,
    postLogoutRedirectUris: patch.postLogoutRedirectUris ?? current.postLogoutRedirectUris,
    allowedScopes: patch.allowedScopes ?? current.allowedScopes,
    allowedGrantTypes: patch.allowedGrantTypes ?? current.allowedGrantTypes,
    allowedResources: patch.allowedResources ?? current.allowedResources,
    defaultResource:
      patch.defaultResource === undefined ? current.defaultResource : patch.defaultResource,
    requirePkce: true,
    introspectionAllowed: patch.introspectionAllowed ?? current.introspectionAllowed,
  }
  await env.DB.prepare(
    `UPDATE oauth_clients SET name = ?, redirect_uris_json = ?, post_logout_redirect_uris_json = ?,
       allowed_scopes_json = ?,
       allowed_grant_types_json = ?, allowed_resources_json = ?, default_resource = ?,
       require_pkce = ?, introspection_allowed = ?, updated_at = ? WHERE client_id = ?`,
  )
    .bind(
      next.name,
      JSON.stringify(next.redirectUris),
      JSON.stringify(next.postLogoutRedirectUris),
      JSON.stringify(next.allowedScopes),
      JSON.stringify(next.allowedGrantTypes),
      JSON.stringify(next.allowedResources),
      next.defaultResource,
      1,
      next.introspectionAllowed ? 1 : 0,
      nowSeconds(),
      id,
    )
    .run()
  return true
}

export async function deleteClient(env: Env, id: string): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM oauth_clients WHERE client_id = ?")
    .bind(id)
    .run()
  return result.meta.changes >= 1
}

export async function setClientEnabled(env: Env, id: string, enabled: boolean): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE oauth_clients SET enabled = ?, updated_at = ? WHERE client_id = ?",
  )
    .bind(enabled ? 1 : 0, nowSeconds(), id)
    .run()
  return result.meta.changes === 1
}

export async function setClientSecretHash(
  env: Env,
  id: string,
  secretHash: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE oauth_clients SET client_secret_hash = ?, updated_at = ? WHERE client_id = ?",
  )
    .bind(secretHash, nowSeconds(), id)
    .run()
  return result.meta.changes === 1
}

const MAX_METADATA_CLIENT_RECORDS = 10_000

export type UpsertMetadataClientInput = {
  readonly clientId: string
  readonly name: string
  readonly redirectUris: readonly string[]
  readonly allowedGrantTypes: readonly string[]
  readonly tokenEndpointAuthMethods: readonly TokenEndpointAuthMethod[]
  readonly metadataJwksUri: string | null
  readonly metadataFingerprint: string
  readonly resourceUri: string
  readonly resourceScopes: readonly string[]
  readonly metadataExpiresAt: number
}

/**
 * Persist the runtime projection of a discovered metadata document. The
 * registration type and fingerprint keep external metadata distinct from
 * administrator-managed clients; resource policy, approval, user entitlement,
 * and consent remain independent gates.
 */
export async function upsertMetadataClient(
  env: Env,
  input: UpsertMetadataClientInput,
): Promise<OAuthClient> {
  const existing = await getClientById(env, input.clientId)
  if (existing !== null && existing.registrationType !== "client_id_metadata") {
    throw new Error("Client Identifier URL conflicts with a static client registration")
  }
  if (existing === null) {
    const count =
      (await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM oauth_clients WHERE registration_type = 'client_id_metadata'",
      ).first<number>("count")) ?? 0
    if (count >= MAX_METADATA_CLIENT_RECORDS) {
      throw new Error("Metadata client record capacity reached")
    }
  }

  const now = nowSeconds()
  const clientType = input.tokenEndpointAuthMethods.includes("none") ? "public" : "confidential"
  await env.DB.prepare(
    `INSERT OR IGNORE INTO oauth_clients
       (client_id, name, client_secret_hash, type, client_kind, redirect_uris_json,
        post_logout_redirect_uris_json, allowed_scopes_json, allowed_grant_types_json,
        allowed_resources_json, default_resource, require_pkce, enabled,
        registration_type, metadata_expires_at, metadata_fingerprint,
        token_endpoint_auth_methods_json, metadata_jwks_uri, introspection_allowed,
        created_at, updated_at)
     VALUES (?, ?, NULL, ?, 'application', ?, '[]', ?, ?, ?, NULL, 1, 1,
             'client_id_metadata', ?, ?, ?, ?, 0, ?, ?)`,
  )
    .bind(
      input.clientId,
      input.name,
      clientType,
      JSON.stringify(input.redirectUris),
      JSON.stringify(input.resourceScopes),
      JSON.stringify(input.allowedGrantTypes),
      JSON.stringify([input.resourceUri]),
      input.metadataExpiresAt,
      input.metadataFingerprint,
      JSON.stringify(input.tokenEndpointAuthMethods),
      input.metadataJwksUri,
      now,
      now,
    )
    .run()

  const current = await getClientById(env, input.clientId)
  if (current === null || current.registrationType !== "client_id_metadata") {
    throw new Error("Metadata client could not be persisted")
  }
  const allowedResources = [...new Set([...current.allowedResources, input.resourceUri])]
  const allowedScopes = [...new Set([...current.allowedScopes, ...input.resourceScopes])]
  const metadataChanged = current.metadataFingerprint !== input.metadataFingerprint

  const statements = [
    env.DB.prepare(
      `UPDATE oauth_clients
         SET name = ?, type = ?, redirect_uris_json = ?, allowed_scopes_json = ?,
             allowed_grant_types_json = ?, allowed_resources_json = ?,
             metadata_expires_at = ?, metadata_fingerprint = ?,
             token_endpoint_auth_methods_json = ?, metadata_jwks_uri = ?, updated_at = ?
         WHERE client_id = ? AND registration_type = 'client_id_metadata'`,
    ).bind(
      input.name,
      clientType,
      JSON.stringify(input.redirectUris),
      JSON.stringify(allowedScopes),
      JSON.stringify(input.allowedGrantTypes),
      JSON.stringify(allowedResources),
      input.metadataExpiresAt,
      input.metadataFingerprint,
      JSON.stringify(input.tokenEndpointAuthMethods),
      input.metadataJwksUri,
      now,
      input.clientId,
    ),
  ]
  if (metadataChanged) {
    statements.push(
      env.DB.prepare(
        `UPDATE refresh_tokens SET revoked_at = ?
         WHERE client_id = ? AND revoked_at IS NULL`,
      ).bind(now, input.clientId),
      env.DB.prepare(
        `UPDATE authorization_grants SET revoked_at = ?
         WHERE client_id = ? AND revoked_at IS NULL`,
      ).bind(now, input.clientId),
    )
  }
  await env.DB.batch(statements)
  const updated = await getClientById(env, input.clientId)
  if (updated === null) throw new Error("Metadata client disappeared after registration")
  return updated
}

export async function isMetadataClientApproved(
  env: Env,
  clientId: string,
  resourceUri: string,
): Promise<boolean> {
  return (
    (await env.DB.prepare(
      `SELECT 1 FROM oauth_metadata_client_approvals
       WHERE client_id = ? AND resource_uri = ?`,
    )
      .bind(clientId, resourceUri)
      .first()) !== null
  )
}

export async function approveMetadataClient(
  env: Env,
  clientId: string,
  resourceUri: string,
  approvedByUserId: string | null,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `INSERT INTO oauth_metadata_client_approvals
       (client_id, resource_uri, approved_by_user_id, approved_at)
     SELECT client.client_id, resource.resource_uri, ?, ?
     FROM oauth_clients AS client
     JOIN oauth_resources AS resource ON resource.resource_uri = ?
     WHERE client.client_id = ?
       AND client.registration_type = 'client_id_metadata'
       AND resource.metadata_client_policy = 'admin_approved'
       AND EXISTS (
         SELECT 1 FROM json_each(client.allowed_resources_json)
         WHERE CAST(value AS TEXT) = resource.resource_uri
       )
     ON CONFLICT(client_id, resource_uri) DO UPDATE SET
       approved_by_user_id = excluded.approved_by_user_id,
       approved_at = excluded.approved_at`,
  )
    .bind(approvedByUserId, nowSeconds(), resourceUri, clientId)
    .run()
  return result.meta.changes >= 1
}

export async function revokeMetadataClientApproval(
  env: Env,
  clientId: string,
  resourceUri: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `DELETE FROM oauth_metadata_client_approvals
     WHERE client_id = ? AND resource_uri = ?`,
  )
    .bind(clientId, resourceUri)
    .run()
  return result.meta.changes >= 1
}

export async function listMetadataClientApprovals(
  env: Env,
  clientId: string,
): Promise<readonly string[]> {
  const result = await env.DB.prepare(
    `SELECT resource_uri FROM oauth_metadata_client_approvals
     WHERE client_id = ? ORDER BY resource_uri`,
  )
    .bind(clientId)
    .all<{ resource_uri: string }>()
  return result.results.map((row) => row.resource_uri)
}
