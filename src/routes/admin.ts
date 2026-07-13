import { Hono } from "hono"
import { registerAdminClients } from "../admin/clients"
import { registerAdminCatalog } from "../admin/device-sessions"
import { registerAdminUsers } from "../admin/users"
import { requireAdmin, requireAdminMutationIntegrity } from "../middleware/admin"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"

export const admin = new Hono<AppBindings>()

admin.use("/admin/*", requireAdmin, requireAdminMutationIntegrity)

admin.get("/admin/csrf", (c) => c.json({ csrf_token: issueCsrfToken(c) }))

registerAdminUsers(admin)
registerAdminClients(admin)
registerAdminCatalog(admin)
