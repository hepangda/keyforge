import type { Context } from "hono"
import { Hono } from "hono"
import { z } from "zod"
import { createEmailChangeToken, createEmailVerificationToken } from "../auth/account-tokens"
import { getProviderCredentials } from "../auth/oauth-providers"
import {
  changeUserPasswordKeepingSession,
  userHasPassword,
  verifyUserPassword,
} from "../auth/password"
import { deleteIdentityPreservingLoginMethod } from "../db/queries/identities"
import { deleteUserPreservingActiveAdmin, getUserByEmail, updateUser } from "../db/queries/users"
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

const SOCIAL_PROVIDERS = new Set(["github", "google"])
const emailSchema = z.email().max(254)

function currentUser(c: Context<AppBindings>): User | null {
  return c.get("user") ?? null
}

async function verifiedForm(c: Context<AppBindings>): Promise<FormData | null> {
  const form = await c.req.raw.formData()
  return verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined) ? form : null
}

function configuredSocialProviders(env: Env): ("github" | "google")[] {
  return (["github", "google"] as const).filter(
    (provider) => getProviderCredentials(env, provider) !== null,
  )
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

accountSecurity.post("/account/password", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=profile&notice=invalid")
  const password = readFormField(form, "new_password")
  const confirmation = readFormField(form, "new_password_confirm")
  const authorization = await authorizeSensitivePasswordAction(c, user, form, "change_password")
  if (authorization === "reauthentication_required") {
    return c.redirect(reauthenticationRedirect("/?section=profile"))
  }
  if (
    authorization !== "authorized" ||
    password.length < 12 ||
    password.length > 128 ||
    password !== confirmation
  ) {
    return c.redirect("/?section=profile&notice=password_invalid")
  }
  const currentSession = c.get("session")
  if (
    currentSession === undefined ||
    !(await changeUserPasswordKeepingSession(c.env, user.id, password, currentSession.id))
  ) {
    return c.redirect("/?section=profile&notice=password_invalid")
  }
  await recordAudit(c.env, {
    type: "user.password.changed",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.redirect("/?section=profile&notice=password_changed")
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
  if (user === null || form === null) return c.redirect("/?section=passkeys&notice=invalid")
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
  return c.redirect(`/?section=passkeys&notice=${renamed ? "passkey_renamed" : "not_found"}`)
})

accountSecurity.post("/account/passkeys/:id/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=passkeys&notice=invalid")
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect("/login?reauth=1&return_to=%2F%3Fsection%3Dpasskeys")
  }
  const result = await deleteCredentialPreservingLoginMethod(
    c.env,
    c.req.param("id"),
    user.id,
    configuredSocialProviders(c.env),
  )
  if (result === "deleted") {
    await recordAudit(c.env, {
      type: "user.passkey.updated",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "passkey deleted",
    })
  }
  return c.redirect(
    `/?section=passkeys&notice=${
      result === "deleted"
        ? "passkey_deleted"
        : result === "last_login_method"
          ? "last_login_method"
          : "not_found"
    }`,
  )
})

accountSecurity.post("/account/identities/:provider/unlink", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  const provider = c.req.param("provider")
  if (user === null || form === null || !SOCIAL_PROVIDERS.has(provider)) {
    return c.redirect("/?section=identities&notice=invalid")
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect("/login?reauth=1&return_to=%2F%3Fsection%3Didentities")
  }
  const result = await deleteIdentityPreservingLoginMethod(
    c.env,
    user.id,
    provider,
    configuredSocialProviders(c.env),
  )
  if (result === "deleted") {
    await recordAudit(c.env, {
      type: "user.identity.unlinked",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: `unlinked ${provider}`,
    })
  }
  return c.redirect(
    `/?section=identities&notice=${
      result === "deleted"
        ? "identity_unlinked"
        : result === "last_login_method"
          ? "last_login_method"
          : "not_found"
    }`,
  )
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
