import type { Hono } from "hono"
import { countDeviceSessions } from "../db/queries/admin-devices"
import { listAuditLogs } from "../db/queries/audit"
import { listClients } from "../db/queries/clients"
import { listResources } from "../db/queries/resources"
import { countUsers } from "../db/queries/users"
import type { AppBindings } from "../types/app"
import { renderOverview } from "../views/console/overview"
import { chrome } from "./shared"

export function registerConsoleOverview(app: Hono<AppBindings>): void {
  app.get("/console", async (c) => {
    const [users, clients, resources, devices, recent] = await Promise.all([
      countUsers(c.env),
      listClients(c.env),
      listResources(c.env),
      countDeviceSessions(c.env),
      listAuditLogs(c.env, { limit: 8, offset: 0 }),
    ])
    return c.html(
      renderOverview(
        chrome(c, "overview"),
        {
          users,
          clients: clients.length,
          resources: resources.length,
          enabledResources: resources.filter((resource) => resource.enabled).length,
          devices,
        },
        recent,
      ),
    )
  })
}
