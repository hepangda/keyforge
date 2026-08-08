import { Hono } from "hono"
import { registerAdminClients } from "../admin/clients"
import { registerAdminCatalog } from "../admin/device-sessions"
import { registerAdminUsers } from "../admin/users"
import { requireAdminApiToken } from "../middleware/admin"
import type { AppBindings } from "../types/app"

export const admin = new Hono<AppBindings>()

admin.use("/admin/*", requireAdminApiToken)

registerAdminUsers(admin)
registerAdminClients(admin)
registerAdminCatalog(admin)
