import * as z from "zod"
import type { ClientKind, ClientType, OAuthClient } from "../../types/domain"
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
})

const stringArraySchema = z.array(z.string())

function parseJsonStringArray(raw: string): string[] {
  const result = stringArraySchema.safeParse(JSON.parse(raw))
  return result.success ? result.data : []
}

const CLIENT_COLUMNS = `client_id, name, client_secret_hash, type, client_kind, redirect_uris_json,
  post_logout_redirect_uris_json,
  allowed_scopes_json, allowed_grant_types_json, allowed_resources_json,
  default_resource, require_pkce, enabled`

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
    enabled: parsed.enabled === 1,
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
        default_resource, require_pkce, enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
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
  }
  await env.DB.prepare(
    `UPDATE oauth_clients SET name = ?, redirect_uris_json = ?, post_logout_redirect_uris_json = ?,
       allowed_scopes_json = ?,
       allowed_grant_types_json = ?, allowed_resources_json = ?, default_resource = ?,
       require_pkce = ?, updated_at = ? WHERE client_id = ?`,
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
