import * as z from "zod"

export type AdminOverviewCounts = {
  readonly users: number
  readonly clients: number
  readonly resources: number
  readonly enabledResources: number
  readonly devices: number
}

const overviewRowSchema = z.object({
  users: z.number(),
  clients: z.number(),
  resources: z.number(),
  enabled_resources: z.number(),
  devices: z.number(),
})

export async function getAdminOverviewCounts(env: Env): Promise<AdminOverviewCounts> {
  const row = overviewRowSchema.parse(
    await env.DB.prepare(
      `SELECT
         (SELECT COUNT(*) FROM users) AS users,
         (SELECT COUNT(*) FROM oauth_clients) AS clients,
         (SELECT COUNT(*) FROM oauth_resources) AS resources,
         (SELECT COUNT(*) FROM oauth_resources WHERE enabled = 1) AS enabled_resources,
         (SELECT COUNT(*) FROM device_authorization_sessions) AS devices`,
    ).first(),
  )
  return {
    users: row.users,
    clients: row.clients,
    resources: row.resources,
    enabledResources: row.enabled_resources,
    devices: row.devices,
  }
}
