import type { Hono } from "hono"
import { listDeviceSessions, revokeDeviceSession } from "../db/queries/admin-devices"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import { parsePagination } from "../utils/http"
import { renderDevicesList } from "../views/console/devices"
import { chrome, readVerifiedForm } from "./shared"

export function registerConsoleDevices(app: Hono<AppBindings>): void {
  app.get("/console/devices", async (c) => {
    const { limit, offset } = parsePagination(c)
    const devicePage = await listDeviceSessions(c.env, limit + 1, offset)
    const hasNext = devicePage.length > limit
    const devices = devicePage.slice(0, limit)
    return c.html(
      renderDevicesList(chrome(c, "devices"), devices, issueCsrfToken(c), limit, offset, hasNext),
    )
  })

  app.post("/console/devices/:id/revoke", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect("/console/devices?flash=invalid")
    }
    const id = c.req.param("id")
    if (!(await revokeDeviceSession(c.env, id))) {
      return c.redirect("/console/devices?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.device.revoked",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      detail: `console revoked device session ${id}`,
    })
    return c.redirect("/console/devices?flash=device_revoked")
  })
}
