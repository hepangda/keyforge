import { Hono } from "hono"
import { registerConsoleAudit } from "../console/audit"
import { registerConsoleClients } from "../console/clients"
import { registerConsoleDevices } from "../console/devices"
import { registerConsoleOverview } from "../console/overview"
import { registerConsoleResources } from "../console/resources"
import { registerConsoleUsers } from "../console/users"
import { requireConsoleAdmin } from "../middleware/console-admin"
import type { AppBindings } from "../types/app"

export const adminConsole = new Hono<AppBindings>()

adminConsole.use("/console", requireConsoleAdmin)
adminConsole.use("/console/*", requireConsoleAdmin)

registerConsoleOverview(adminConsole)
registerConsoleUsers(adminConsole)
registerConsoleClients(adminConsole)
registerConsoleResources(adminConsole)
registerConsoleDevices(adminConsole)
registerConsoleAudit(adminConsole)
