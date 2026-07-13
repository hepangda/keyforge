import type { Hono } from "hono"
import { type AuditLogQuery, listAuditLogs } from "../db/queries/audit"
import type { AppBindings } from "../types/app"
import { parsePagination } from "../utils/http"
import { renderAuditList } from "../views/console/audit"
import { chrome } from "./shared"

export function registerConsoleAudit(app: Hono<AppBindings>): void {
  app.get("/console/audit", async (c) => {
    const { limit, offset } = parsePagination(c)
    const filters = {
      eventType: c.req.query("event_type") ?? "",
      userId: c.req.query("user_id") ?? "",
      clientId: c.req.query("client_id") ?? "",
      actorUserId: c.req.query("actor_user_id") ?? "",
      actorClientId: c.req.query("actor_client_id") ?? "",
    }
    const query: { -readonly [K in keyof AuditLogQuery]: AuditLogQuery[K] } = {
      limit: limit + 1,
      offset,
    }
    if (filters.eventType !== "") {
      query.eventType = filters.eventType
    }
    if (filters.userId !== "") {
      query.userId = filters.userId
    }
    if (filters.clientId !== "") {
      query.clientId = filters.clientId
    }
    if (filters.actorUserId !== "") {
      query.actorUserId = filters.actorUserId
    }
    if (filters.actorClientId !== "") {
      query.actorClientId = filters.actorClientId
    }
    const logPage = await listAuditLogs(c.env, query)
    const hasNext = logPage.length > limit
    const logs = logPage.slice(0, limit)
    return c.html(renderAuditList(chrome(c, "audit"), logs, filters, limit, offset, hasNext))
  })
}
