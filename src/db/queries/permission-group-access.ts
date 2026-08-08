import * as z from "zod"

export const MAX_PERMISSION_GROUP_TARGETS = 100

export type PermissionGroupAccess = {
  readonly clientIds: readonly string[]
  readonly resourceUris: readonly string[]
}

const accessRowSchema = z.object({
  client_ids_json: z.string(),
  resource_uris_json: z.string(),
})
const stringArraySchema = z.array(z.string())
const groupRowsSchema = z.array(z.object({ id: z.string() }))
const clientRowsSchema = z.array(
  z.object({
    client_id: z.string(),
    client_kind: z.enum(["application", "device", "service"]),
  }),
)
const resourceRowsSchema = z.array(z.object({ resource_uri: z.string() }))

export async function getPermissionGroupAccess(
  env: Env,
  groupId: string,
): Promise<PermissionGroupAccess | null> {
  const row = await env.DB.prepare(
    `SELECT
       (
         SELECT json_group_array(client_id)
         FROM (
           SELECT client_id
           FROM oauth_client_permission_groups
           WHERE group_id = permission_group.id
           ORDER BY client_id
         )
       ) AS client_ids_json,
       (
         SELECT json_group_array(resource_uri)
         FROM (
           SELECT resource_uri
           FROM oauth_resource_permission_groups
           WHERE group_id = permission_group.id
           ORDER BY resource_uri
         )
       ) AS resource_uris_json
     FROM groups AS permission_group
     WHERE permission_group.id = ?`,
  )
    .bind(groupId)
    .first()
  if (row === null) return null

  const parsed = accessRowSchema.parse(row)
  return {
    clientIds: stringArraySchema.parse(JSON.parse(parsed.client_ids_json)),
    resourceUris: stringArraySchema.parse(JSON.parse(parsed.resource_uris_json)),
  }
}

export async function replacePermissionGroupAccess(
  env: Env,
  groupId: string,
  access: PermissionGroupAccess,
): Promise<"updated" | "not_found" | "invalid_client" | "invalid_resource"> {
  const clientIds = [...new Set(access.clientIds)]
  const resourceUris = [...new Set(access.resourceUris)]
  if (clientIds.length > MAX_PERMISSION_GROUP_TARGETS) {
    throw new RangeError(
      `a permission group may target at most ${MAX_PERMISSION_GROUP_TARGETS} clients`,
    )
  }
  if (resourceUris.length > MAX_PERMISSION_GROUP_TARGETS) {
    throw new RangeError(
      `a permission group may target at most ${MAX_PERMISSION_GROUP_TARGETS} resources`,
    )
  }

  const clientIdsJson = JSON.stringify(clientIds)
  const resourceUrisJson = JSON.stringify(resourceUris)
  const [groupResult, clientResult, resourceResult] = await env.DB.batch([
    env.DB.prepare("SELECT id FROM groups WHERE id = ?").bind(groupId),
    env.DB.prepare(
      `SELECT client_id, client_kind
         FROM oauth_clients
         WHERE client_id IN (SELECT CAST(value AS TEXT) FROM json_each(?))`,
    ).bind(clientIdsJson),
    env.DB.prepare(
      `SELECT resource_uri
         FROM oauth_resources
         WHERE resource_uri IN (SELECT CAST(value AS TEXT) FROM json_each(?))`,
    ).bind(resourceUrisJson),
  ])

  const groupRows = groupRowsSchema.safeParse(groupResult?.results)
  if (!groupRows.success || groupRows.data.length !== 1) return "not_found"

  const clientRows = clientRowsSchema.safeParse(clientResult?.results)
  if (
    !clientRows.success ||
    clientRows.data.length !== clientIds.length ||
    clientRows.data.some((client) => client.client_kind === "service")
  ) {
    return "invalid_client"
  }

  const resourceRows = resourceRowsSchema.safeParse(resourceResult?.results)
  if (!resourceRows.success || resourceRows.data.length !== resourceUris.length) {
    return "invalid_resource"
  }

  await env.DB.batch([
    env.DB.prepare("DELETE FROM oauth_client_permission_groups WHERE group_id = ?").bind(groupId),
    env.DB.prepare(
      `INSERT INTO oauth_client_permission_groups (client_id, group_id, created_at)
         SELECT CAST(value AS TEXT), ?, unixepoch()
         FROM json_each(?)`,
    ).bind(groupId, clientIdsJson),
    env.DB.prepare("DELETE FROM oauth_resource_permission_groups WHERE group_id = ?").bind(groupId),
    env.DB.prepare(
      `INSERT INTO oauth_resource_permission_groups (resource_uri, group_id, created_at)
         SELECT CAST(value AS TEXT), ?, unixepoch()
         FROM json_each(?)`,
    ).bind(groupId, resourceUrisJson),
  ])
  return "updated"
}
