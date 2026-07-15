import type { Context } from "hono"
import { Hono } from "hono"
import { z } from "zod"
import { createEmailChangeToken, createEmailVerificationToken } from "../auth/account-tokens"
import {
  addUserPassword,
  deletePasswordCredentialPreservingLoginMethod,
  minimumPasswordLength,
  PASSWORD_POLICY,
  renamePasswordCredential,
  userHasPassword,
  verifyUserPassword,
} from "../auth/password"
import {
  ALIAS_PATTERN,
  deleteUserPreservingActiveAdmin,
  getUserByEmail,
  isUserAdmin,
  MAX_ALIAS_LENGTH,
  updateUser,
  updateUserAlias,
} from "../db/queries/users"
import { deleteCredentialPreservingLoginMethod, renameCredential } from "../db/queries/webauthn"
import { enqueueEmail } from "../email/sender"
import { emailChangeEmail, emailVerificationEmail } from "../email/templates"
import { requireAuth } from "../middleware/session"
import { recordAudit } from "../security/audit"
import { clearSessionCookie } from "../security/cookies"
import { verifyCsrfToken } from "../security/csrf"
import { checkRateLimit, shouldAuditRateLimit } from "../security/rate-limit"
import { hasRecentAuthentication } from "../security/recent-auth"
import { clientIpHash } from "../security/request-meta"
import type { AppBindings } from "../types/app"
import type { User } from "../types/domain"
import { readFormField } from "../utils/form"

export const accountSecurity = new Hono<AppBindings>()

accountSecurity.use("/account/*", requireAuth)

const emailSchema = z.email().max(254)

function currentUser(c: Context<AppBindings>): User | null {
  return c.get("user") ?? null
}

async function verifiedForm(c: Context<AppBindings>): Promise<FormData | null> {
  const form = await c.req.raw.formData()
  return verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined) ? form : null
}

async function authorizeSensitivePasswordAction(
  c: Context<AppBindings>,
  user: User,
  form: FormData,
  action: string,
): Promise<"authorized" | "denied" | "reauthentication_required"> {
  if (!(await userHasPassword(c.env, user.id))) {
    return hasRecentAuthentication(c.get("session")) ? "authorized" : "reauthentication_required"
  }
  const ipHash = await clientIpHash(c)
  const rate = await checkRateLimit(
    c.env,
    `account-password:${user.id}:${ipHash ?? "unknown"}`,
    10,
    15 * 60,
  )
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    if (shouldAuditRateLimit(rate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        userId: user.id,
        requestId: c.get("requestId"),
        ipHash,
        success: false,
        detail: `sensitive account action rate limited: ${action}`,
      })
    }
    return "denied"
  }
  const verified = await verifyUserPassword(c.env, user.id, readFormField(form, "current_password"))
  if (!verified) {
    await recordAudit(c.env, {
      type: "user.login.password.failure",
      userId: user.id,
      requestId: c.get("requestId"),
      ipHash,
      success: false,
      detail: `current password rejected for sensitive account action: ${action}`,
    })
  }
  return verified ? "authorized" : "denied"
}

function reauthenticationRedirect(returnTo: string): string {
  return `/login?reauth=1&return_to=${encodeURIComponent(returnTo)}`
}

accountSecurity.post("/account/profile", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=profile&notice=invalid")
  const alias = readFormField(form, "alias").trim()
  if (!ALIAS_PATTERN.test(alias) || alias.length > MAX_ALIAS_LENGTH) {
    return c.redirect("/?section=profile&notice=alias_invalid")
  }
  if ((await updateUserAlias(c.env, user.id, alias)) !== "updated") {
    return c.redirect("/?section=profile&notice=alias_invalid")
  }
  const rawName = readFormField(form, "name").trim()
  await updateUser(c.env, user.id, { name: rawName === "" ? null : rawName.slice(0, 120) })
  await recordAudit(c.env, {
    type: "user.profile.updated",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.redirect("/?section=profile&notice=profile_updated")
})

accountSecurity.post("/account/passwords", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect("/?section=login-methods&notice=invalid")
  }
  const authorization = await authorizeSensitivePasswordAction(c, user, form, "add_password")
  if (authorization === "reauthentication_required") {
    return c.redirect(reauthenticationRedirect("/?section=login-methods"))
  }
  const password = readFormField(form, "password")
  const confirmation = readFormField(form, "password_confirm")
  const administrator = await isUserAdmin(c.env, user.id)
  const minimum = minimumPasswordLength(administrator)
  if (
    authorization !== "authorized" ||
    password.length < minimum ||
    password.length > PASSWORD_POLICY.maximum ||
    password !== confirmation
  ) {
    return c.redirect("/?section=login-methods&notice=password_invalid")
  }
  const rawName = readFormField(form, "name").trim()
  if ((await addUserPassword(c.env, user.id, password, rawName === "" ? null : rawName)) === null) {
    return c.redirect("/?section=login-methods&notice=password_invalid")
  }
  await recordAudit(c.env, {
    type: "user.password.changed",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
    detail: "password login method added",
  })
  return c.redirect("/?section=login-methods&notice=password_added")
})

accountSecurity.post("/account/passwords/:id/rename", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect("/?section=login-methods&notice=invalid")
  }
  const rawName = readFormField(form, "name").trim()
  const renamed = await renamePasswordCredential(
    c.env,
    c.req.param("id"),
    user.id,
    rawName === "" ? null : rawName,
  )
  if (renamed) {
    await recordAudit(c.env, {
      type: "user.password.changed",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "password login method renamed",
    })
  }
  return c.redirect(`/?section=login-methods&notice=${renamed ? "password_renamed" : "not_found"}`)
})

accountSecurity.post("/account/passwords/:id/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect("/?section=login-methods&notice=invalid")
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(reauthenticationRedirect("/?section=login-methods"))
  }
  const result = await deletePasswordCredentialPreservingLoginMethod(
    c.env,
    c.req.param("id"),
    user.id,
  )
  if (result === "deleted") {
    await recordAudit(c.env, {
      type: "user.password.changed",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "password login method deleted",
    })
  }
  const notice =
    result === "deleted"
      ? "password_deleted"
      : result === "last_login_method"
        ? "last_login_method"
        : "not_found"
  return c.redirect(`/?section=login-methods&notice=${notice}`)
})

accountSecurity.post("/account/email/verify", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=profile&notice=invalid")
  if (user.emailVerified) return c.redirect("/?section=profile&notice=email_verified")
  try {
    const { url } = await createEmailVerificationToken(c.env, user.id, user.email)
    await enqueueEmail(c.env, { to: user.email, ...emailVerificationEmail(url) })
    await recordAudit(c.env, {
      type: "user.email.verification.requested",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect("/?section=profile&notice=verification_sent")
  } catch (error) {
    console.error("email.verification_failed", c.get("requestId"), error)
    return c.redirect("/?section=profile&notice=email_unavailable")
  }
})

accountSecurity.post("/account/email/change", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=profile&notice=invalid")
  const parsedEmail = emailSchema.safeParse(readFormField(form, "new_email").trim().toLowerCase())
  if (!parsedEmail.success) {
    return c.redirect("/?section=profile&notice=email_change_invalid")
  }
  const newEmail = parsedEmail.data
  if (newEmail === user.email || (await getUserByEmail(c.env, newEmail)) !== null) {
    return c.redirect("/?section=profile&notice=email_change_invalid")
  }
  const authorization = await authorizeSensitivePasswordAction(c, user, form, "change_email")
  if (authorization === "reauthentication_required") {
    return c.redirect(reauthenticationRedirect("/?section=profile"))
  }
  if (authorization !== "authorized") {
    return c.redirect("/?section=profile&notice=email_change_invalid")
  }
  try {
    const { url } = await createEmailChangeToken(c.env, user.id, newEmail)
    await enqueueEmail(c.env, { to: newEmail, ...emailChangeEmail(url) })
    await recordAudit(c.env, {
      type: "user.email.change.requested",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "email change confirmation sent",
    })
    return c.redirect("/?section=profile&notice=email_change_sent")
  } catch (error) {
    console.error("email.change_failed", c.get("requestId"), error)
    return c.redirect("/?section=profile&notice=email_unavailable")
  }
})

accountSecurity.post("/account/passkeys/:id/rename", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect("/?section=login-methods&notice=invalid")
  }
  const rawName = readFormField(form, "name").trim()
  const renamed = await renameCredential(
    c.env,
    c.req.param("id"),
    user.id,
    rawName === "" ? null : rawName.slice(0, 80),
  )
  if (renamed) {
    await recordAudit(c.env, {
      type: "user.passkey.updated",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "passkey renamed",
    })
  }
  return c.redirect(`/?section=login-methods&notice=${renamed ? "passkey_renamed" : "not_found"}`)
})

accountSecurity.post("/account/passkeys/:id/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect("/?section=login-methods&notice=invalid")
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(reauthenticationRedirect("/?section=login-methods"))
  }
  const result = await deleteCredentialPreservingLoginMethod(c.env, c.req.param("id"), user.id)
  if (result === "deleted") {
    await recordAudit(c.env, {
      type: "user.passkey.updated",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "passkey deleted",
    })
  }
  const notice =
    result === "deleted"
      ? "passkey_deleted"
      : result === "last_login_method"
        ? "last_login_method"
        : "not_found"
  return c.redirect(`/?section=login-methods&notice=${notice}`)
})

accountSecurity.post("/account/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=profile&notice=invalid")
  const confirmed = readFormField(form, "confirmation") === user.email
  const authorization = await authorizeSensitivePasswordAction(c, user, form, "delete_account")
  if (authorization === "reauthentication_required") {
    return c.redirect(reauthenticationRedirect("/?section=profile"))
  }
  if (!confirmed || authorization !== "authorized") {
    return c.redirect("/?section=profile&notice=delete_invalid")
  }
  if (!(await deleteUserPreservingActiveAdmin(c.env, user.id))) {
    return c.redirect("/?section=profile&notice=last_active_admin")
  }
  await recordAudit(c.env, {
    type: "user.deleted",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  clearSessionCookie(c)
  return c.redirect("/login?notice=account_deleted")
})
