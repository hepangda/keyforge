import { z } from "zod"
import type { OAuthResource } from "../../types/domain"
import { asResourceUri } from "../../types/domain"
import { nowSeconds } from "../../utils/time"

const resourceRowSchema = z.object({
  resource_uri: z.string(),
  name: z.string(),
  allowed_scopes_json: z.string(),
  enabled: z.number(),
})

const stringArraySchema = z.array(z.string())

const RESOURCE_COLUMNS = "resource_uri, name, allowed_scopes_json, enabled"

function mapResource(row: unknown): OAuthResource {
  const parsed = resourceRowSchema.parse(row)
  const scopes = stringArraySchema.safeParse(JSON.parse(parsed.allowed_scopes_json))
  return {
    resourceUri: asResourceUri(parsed.resource_uri),
    name: parsed.name,
    allowedScopes: scopes.success ? scopes.data : [],
    enabled: parsed.enabled === 1,
  }
}

export async function getResourceByUri(
  env: Env,
  resourceUri: string,
): Promise<OAuthResource | null> {
  const row = await env.DB.prepare(
    `SELECT ${RESOURCE_COLUMNS} FROM oauth_resources WHERE resource_uri = ?`,
  )
    .bind(resourceUri)
    .first()
  return row === null ? null : mapResource(row)
}

export async function listResources(env: Env): Promise<OAuthResource[]> {
  const result = await env.DB.prepare(
    `SELECT ${RESOURCE_COLUMNS} FROM oauth_resources ORDER BY created_at DESC`,
  ).all()
  return result.results.map(mapResource)
}

export type CreateResourceInput = {
  readonly resourceUri: string
  readonly name: string
  readonly allowedScopes: readonly string[]
}

export async function createResource(env: Env, input: CreateResourceInput): Promise<void> {
  const now = nowSeconds()
  await env.DB.prepare(
    `INSERT INTO oauth_resources (resource_uri, name, allowed_scopes_json, enabled, created_at, updated_at)
     VALUES (?, ?, ?, 1, ?, ?)`,
  )
    .bind(input.resourceUri, input.name, JSON.stringify(input.allowedScopes), now, now)
    .run()
}

export type ResourcePatch = {
  readonly name?: string
  readonly allowedScopes?: readonly string[]
  readonly enabled?: boolean
}

export async function updateResource(
  env: Env,
  uri: string,
  patch: ResourcePatch,
): Promise<OAuthResource | null> {
  const current = await getResourceByUri(env, uri)
  if (current === null) {
    return null
  }
  const next: OAuthResource = {
    ...current,
    name: patch.name ?? current.name,
    allowedScopes: patch.allowedScopes ?? current.allowedScopes,
    enabled: patch.enabled ?? current.enabled,
  }
  await env.DB.prepare(
    "UPDATE oauth_resources SET name = ?, allowed_scopes_json = ?, enabled = ?, updated_at = ? WHERE resource_uri = ?",
  )
    .bind(next.name, JSON.stringify(next.allowedScopes), next.enabled ? 1 : 0, nowSeconds(), uri)
    .run()
  return next
}

/** Delete an API and retire every D1 authorization path that references it. */
export async function deleteResource(env: Env, resourceUri: string): Promise<boolean> {
  if ((await getResourceByUri(env, resourceUri)) === null) return false

  const [deletion] = await env.DB.batch([
    env.DB.prepare("DELETE FROM oauth_resources WHERE resource_uri = ?").bind(resourceUri),
    env.DB.prepare(
      `UPDATE oauth_clients
         SET allowed_resources_json = (
               SELECT json_group_array(value)
               FROM (
                 SELECT value
                 FROM json_each(oauth_clients.allowed_resources_json)
                 WHERE CAST(value AS TEXT) != ?
                 ORDER BY CAST(key AS INTEGER)
               )
             ),
             default_resource = CASE WHEN default_resource = ? THEN NULL ELSE default_resource END,
             updated_at = unixepoch()
         WHERE default_resource = ?
            OR EXISTS (
              SELECT 1 FROM json_each(oauth_clients.allowed_resources_json)
              WHERE CAST(value AS TEXT) = ?
            )`,
    ).bind(resourceUri, resourceUri, resourceUri, resourceUri),
    env.DB.prepare("DELETE FROM consents WHERE resource = ?").bind(resourceUri),
    env.DB.prepare(
      "UPDATE refresh_tokens SET revoked_at = unixepoch() WHERE resource = ? AND revoked_at IS NULL",
    ).bind(resourceUri),
    env.DB.prepare(
      "UPDATE authorization_grants SET revoked_at = unixepoch() WHERE resource = ? AND revoked_at IS NULL",
    ).bind(resourceUri),
    env.DB.prepare(
      `UPDATE device_authorization_sessions
         SET status = 'denied', denied_at = unixepoch()
         WHERE resource_uri = ? AND status IN ('pending', 'approved')`,
    ).bind(resourceUri),
  ])
  return (deletion?.meta.changes ?? 0) >= 1
}
