import type { Hono } from "hono"
import {
  getDeviceSessionById,
  listDeviceSessions,
  revokeDeviceSession,
} from "../db/queries/admin-devices"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import { parsePagination } from "../utils/http"
import { renderDeviceRevokeConfirmation, renderDevicesList } from "../views/console/devices"
import { chrome, readVerifiedForm } from "./shared"

export function registerConsoleDevices(app: Hono<AppBindings>): void {
  app.get("/console/devices", async (c) => {
    const { limit, offset } = parsePagination(c)
    const devicePage = await listDeviceSessions(c.env, limit + 1, offset)
    const hasNext = devicePage.length > limit
    const devices = devicePage.slice(0, limit)
    return c.html(renderDevicesList(chrome(c, "devices"), devices, limit, offset, hasNext))
  })

  app.get("/console/devices/:id/revoke", async (c) => {
    const device = await getDeviceSessionById(c.env, c.req.param("id"))
    if (device === null || (device.status !== "pending" && device.status !== "approved")) {
      return c.redirect("/console/devices?flash=not_found")
    }
    return c.html(renderDeviceRevokeConfirmation(chrome(c, "devices"), device, issueCsrfToken(c)))
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
