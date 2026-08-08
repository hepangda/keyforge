import type { Hono } from "hono"
import { getAdminOverviewCounts } from "../db/queries/admin-overview"
import { listAuditLogs } from "../db/queries/audit"
import type { AppBindings } from "../types/app"
import { renderOverview } from "../views/console/overview"
import { chrome } from "./shared"

export function registerConsoleOverview(app: Hono<AppBindings>): void {
  app.get("/console", async (c) => {
    const [counts, recent] = await Promise.all([
      getAdminOverviewCounts(c.env),
      listAuditLogs(c.env, { limit: 8, offset: 0 }),
    ])
    return c.html(renderOverview(chrome(c, "overview"), counts, recent))
  })
}
