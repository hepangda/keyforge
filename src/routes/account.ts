import { Hono } from "hono"
import { revokeOtherUserSessions, revokeSessionById } from "../auth/session"
import { deleteConsent } from "../db/queries/consents"
import { revokeAuthorizationGrantsByUserClient } from "../db/queries/grants"
import { revokeDeviceRefreshFamily } from "../db/queries/tokens"
import { requireAuth } from "../middleware/session"
import { recordAudit } from "../security/audit"
import { verifyCsrfToken } from "../security/csrf"
import { revokeRefreshFamiliesByUserClient } from "../tokens/refresh-token-revocation"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"

export const account = new Hono<AppBindings>()

account.use("/account/*", requireAuth)

account.post("/account/sessions/revoke-others", async (c) => {
  const user = c.get("user")
  const session = c.get("session")
  if (user === undefined || session === undefined) {
    return c.redirect("/?section=sessions")
  }
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.redirect("/?section=sessions&notice=invalid")
  }
  const revoked = await revokeOtherUserSessions(c.env, user.id, session.id)
  if (revoked > 0) {
    await recordAudit(c.env, {
      type: "user.logout",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "revoked other sessions",
    })
  }
  return c.redirect(`/?section=sessions&notice=${revoked > 0 ? "sessions_revoked" : "not_found"}`)
})

account.post("/account/sessions/:id/revoke", async (c) => {
  const user = c.get("user")
  if (user === undefined) {
    return c.redirect("/?section=sessions")
  }
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.redirect("/?section=sessions&notice=invalid")
  }
  const revoked = await revokeSessionById(c.env, c.req.param("id"), user.id)
  if (revoked) {
    await recordAudit(c.env, {
      type: "user.logout",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "revoked a session",
    })
  }
  return c.redirect(`/?section=sessions&notice=${revoked ? "session_revoked" : "not_found"}`)
})

account.post("/account/apps/:clientId/revoke", async (c) => {
  const user = c.get("user")
  if (user === undefined) {
    return c.redirect("/?section=apps")
  }
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.redirect("/?section=apps&notice=invalid")
  }
  const clientId = c.req.param("clientId")
  const removed = await deleteConsent(c.env, user.id, clientId)
  const revokedFamilies = await revokeRefreshFamiliesByUserClient(c.env, user.id, clientId)
  const revokedGrants = await revokeAuthorizationGrantsByUserClient(c.env, user.id, clientId)
  const changed = removed || revokedFamilies > 0 || revokedGrants > 0
  if (changed) {
    await recordAudit(c.env, {
      type: "oauth.token.revoked",
      userId: user.id,
      clientId,
      requestId: c.get("requestId"),
      success: true,
      detail: "revoked app consent",
    })
  }
  return c.redirect(`/?section=apps&notice=${changed ? "app_revoked" : "not_found"}`)
})

account.post("/account/devices/:familyId/revoke", async (c) => {
  const user = c.get("user")
  if (user === undefined) return c.redirect("/")
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.redirect("/?section=apps&notice=invalid")
  }
  const familyId = c.req.param("familyId")
  const revoked = await revokeDeviceRefreshFamily(c.env, familyId, user.id)
  if (revoked) {
    await recordAudit(c.env, {
      type: "oauth.token.revoked",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "revoked individual device refresh family",
      metadata: { family_id: familyId },
    })
  }
  return c.redirect(`/?section=apps&notice=${revoked ? "device_revoked" : "not_found"}`)
})
