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
  deleteUserPreservingActiveAdmin,
  getUserByEmail,
  isUserAdmin,
  updateUser,
} from "../db/queries/users"
import { deleteCredentialPreservingLoginMethod, renameCredential } from "../db/queries/webauthn"
import { enqueueEmail } from "../email/sender"
import { emailChangeEmail, emailVerificationEmail } from "../email/templates"
import { avatarPath } from "../media/avatar"
import { type AvatarOutcome, avatarResponse } from "../media/avatar-http"
import { readAvatarUpload, removeUserAvatar, storeUserAvatar } from "../media/avatar-service"
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

function avatarOutcome(reason: "too_large" | "unsupported" | "empty"): AvatarOutcome {
  if (reason === "too_large") return "avatar_too_large"
  return reason === "unsupported" ? "avatar_unsupported" : "avatar_missing"
}

function reauthenticationRedirect(returnTo: string): string {
  return `/login?reauth=1&return_to=${encodeURIComponent(returnTo)}`
}

function accountFlow(
  section: "profile" | "login-methods",
  flow: string,
  options: {
    readonly credentialId?: string
    readonly notice?: string
    readonly verified?: boolean
  } = {},
): string {
  const query = new URLSearchParams({ section, flow })
  if (options.credentialId !== undefined) query.set("credential", options.credentialId)
  if (options.notice !== undefined) query.set("notice", options.notice)
  if (options.verified === true) query.set("verified", "1")
  return `/?${query.toString()}`
}

accountSecurity.post("/account/profile", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect(accountFlow("profile", "edit-profile", { notice: "invalid" }))
  }
  const rawName = readFormField(form, "name").trim()
  await updateUser(c.env, user.id, { name: rawName === "" ? null : rawName.slice(0, 120) })
  await recordAudit(c.env, {
    type: "user.profile.updated",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.redirect(accountFlow("profile", "edit-profile", { notice: "profile_updated" }))
})

accountSecurity.post("/account/avatar", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  const target = accountFlow("profile", "edit-profile")
  const answer = (outcome: AvatarOutcome, extra: Record<string, unknown> = {}): Response =>
    avatarResponse(c, outcome, accountFlow("profile", "edit-profile", { notice: outcome }), extra)
  if (user === null || form === null) {
    return answer("invalid")
  }
  const ipHash = await clientIpHash(c)
  const rate = await checkRateLimit(
    c.env,
    `account-avatar:${user.id}:${ipHash ?? "unknown"}`,
    10,
    60 * 60,
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
        detail: "avatar upload rate limited",
      })
    }
    return answer("avatar_rate_limited", { retry_after: rate.retryAfterSeconds })
  }
  const upload = await readAvatarUpload(form.get("avatar"))
  if (typeof upload === "string") {
    return answer(avatarOutcome(upload))
  }
  const result = await storeUserAvatar(c.env, user.id, upload)
  if (result.status === "rejected") {
    return answer(avatarOutcome(result.reason))
  }
  if (result.status === "not_found") {
    return answer("not_found")
  }
  await recordAudit(c.env, {
    type: "user.profile.updated",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
    detail: "avatar updated",
  })
  return avatarResponse(
    c,
    "avatar_updated",
    accountFlow("profile", "edit-profile", { notice: "avatar_updated" }),
    { picture_url: avatarPath(result.key), return_to: target },
  )
})

accountSecurity.post("/account/avatar/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return avatarResponse(
      c,
      "invalid",
      accountFlow("profile", "edit-profile", { notice: "invalid" }),
    )
  }
  const removed = await removeUserAvatar(c.env, user.id)
  if (removed) {
    await recordAudit(c.env, {
      type: "user.profile.updated",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "avatar removed",
    })
  }
  const outcome: AvatarOutcome = removed ? "avatar_removed" : "not_found"
  return avatarResponse(c, outcome, accountFlow("profile", "edit-profile", { notice: outcome }))
})

accountSecurity.post("/account/passwords", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect(accountFlow("login-methods", "add-password", { notice: "invalid" }))
  }
  const returnTo = accountFlow("login-methods", "add-password", { verified: true })
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(reauthenticationRedirect(returnTo))
  }
  const password = readFormField(form, "password")
  const confirmation = readFormField(form, "password_confirm")
  const administrator = await isUserAdmin(c.env, user.id)
  const minimum = minimumPasswordLength(administrator)
  if (
    password.length < minimum ||
    password.length > PASSWORD_POLICY.maximum ||
    password !== confirmation
  ) {
    return c.redirect(
      accountFlow("login-methods", "add-password", {
        notice: "password_invalid",
        verified: true,
      }),
    )
  }
  const rawName = readFormField(form, "name").trim()
  if ((await addUserPassword(c.env, user.id, password, rawName === "" ? null : rawName)) === null) {
    return c.redirect(
      accountFlow("login-methods", "add-password", {
        notice: "password_invalid",
        verified: true,
      }),
    )
  }
  await recordAudit(c.env, {
    type: "user.password.changed",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
    detail: "password login method added",
  })
  return c.redirect(accountFlow("login-methods", "add-password", { notice: "password_added" }))
})

accountSecurity.post("/account/passwords/:id/rename", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  const credentialId = c.req.param("id")
  if (user === null || form === null) {
    return c.redirect(
      accountFlow("login-methods", "manage-password", {
        credentialId,
        notice: "invalid",
      }),
    )
  }
  const returnTo = accountFlow("login-methods", "manage-password", {
    credentialId,
    verified: true,
  })
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(reauthenticationRedirect(returnTo))
  }
  const rawName = readFormField(form, "name").trim()
  const renamed = await renamePasswordCredential(
    c.env,
    credentialId,
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
  return c.redirect(
    accountFlow("login-methods", "manage-password", {
      credentialId,
      notice: renamed ? "password_renamed" : "not_found",
    }),
  )
})

accountSecurity.post("/account/passwords/:id/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  const credentialId = c.req.param("id")
  if (user === null || form === null) {
    return c.redirect(
      accountFlow("login-methods", "manage-password", {
        credentialId,
        notice: "invalid",
      }),
    )
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(
      reauthenticationRedirect(
        accountFlow("login-methods", "manage-password", {
          credentialId,
          verified: true,
        }),
      ),
    )
  }
  const result = await deletePasswordCredentialPreservingLoginMethod(c.env, credentialId, user.id)
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
  return c.redirect(accountFlow("login-methods", "manage-password", { credentialId, notice }))
})

accountSecurity.post("/account/email/verify", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) return c.redirect("/?section=profile&notice=invalid")
  if (user.emailVerified) return c.redirect("/?section=profile&notice=email_verified")
  try {
    const { url } = await createEmailVerificationToken(c.env, user.id, user.email)
    await enqueueEmail(c.env, {
      to: user.email,
      ...emailVerificationEmail(url, c.get("i18n").locale),
    })
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
  if (user === null || form === null) {
    return c.redirect(accountFlow("profile", "change-email", { notice: "invalid" }))
  }
  const parsedEmail = emailSchema.safeParse(readFormField(form, "new_email").trim().toLowerCase())
  if (!parsedEmail.success) {
    return c.redirect(accountFlow("profile", "change-email", { notice: "email_change_invalid" }))
  }
  const newEmail = parsedEmail.data
  if (newEmail === user.email || (await getUserByEmail(c.env, newEmail)) !== null) {
    return c.redirect(accountFlow("profile", "change-email", { notice: "email_change_invalid" }))
  }
  const authorization = await authorizeSensitivePasswordAction(c, user, form, "change_email")
  if (authorization === "reauthentication_required") {
    return c.redirect(reauthenticationRedirect(accountFlow("profile", "change-email")))
  }
  if (authorization !== "authorized") {
    return c.redirect(accountFlow("profile", "change-email", { notice: "email_change_invalid" }))
  }
  try {
    const { url } = await createEmailChangeToken(c.env, user.id, newEmail)
    await enqueueEmail(c.env, {
      to: newEmail,
      ...emailChangeEmail(url, c.get("i18n").locale),
    })
    await recordAudit(c.env, {
      type: "user.email.change.requested",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "email change confirmation sent",
    })
    return c.redirect(accountFlow("profile", "change-email", { notice: "email_change_sent" }))
  } catch (error) {
    console.error("email.change_failed", c.get("requestId"), error)
    return c.redirect(accountFlow("profile", "change-email", { notice: "email_unavailable" }))
  }
})

accountSecurity.post("/account/passkeys/:id/rename", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  const credentialId = c.req.param("id")
  if (user === null || form === null) {
    return c.redirect(
      accountFlow("login-methods", "manage-passkey", {
        credentialId,
        notice: "invalid",
      }),
    )
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(
      reauthenticationRedirect(
        accountFlow("login-methods", "manage-passkey", {
          credentialId,
          verified: true,
        }),
      ),
    )
  }
  const rawName = readFormField(form, "name").trim()
  const renamed = await renameCredential(
    c.env,
    credentialId,
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
  return c.redirect(
    accountFlow("login-methods", "manage-passkey", {
      credentialId,
      notice: renamed ? "passkey_renamed" : "not_found",
    }),
  )
})

accountSecurity.post("/account/passkeys/:id/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  const credentialId = c.req.param("id")
  if (user === null || form === null) {
    return c.redirect(
      accountFlow("login-methods", "manage-passkey", {
        credentialId,
        notice: "invalid",
      }),
    )
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect(
      reauthenticationRedirect(
        accountFlow("login-methods", "manage-passkey", {
          credentialId,
          verified: true,
        }),
      ),
    )
  }
  const result = await deleteCredentialPreservingLoginMethod(c.env, credentialId, user.id)
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
  return c.redirect(accountFlow("login-methods", "manage-passkey", { credentialId, notice }))
})

accountSecurity.post("/account/delete", async (c) => {
  const user = currentUser(c)
  const form = await verifiedForm(c)
  if (user === null || form === null) {
    return c.redirect(accountFlow("profile", "delete-account", { notice: "invalid" }))
  }
  const confirmed = readFormField(form, "confirmation") === user.email
  const authorization = await authorizeSensitivePasswordAction(c, user, form, "delete_account")
  if (authorization === "reauthentication_required") {
    return c.redirect(reauthenticationRedirect(accountFlow("profile", "delete-account")))
  }
  if (!confirmed || authorization !== "authorized") {
    return c.redirect(accountFlow("profile", "delete-account", { notice: "delete_invalid" }))
  }
  if (!(await deleteUserPreservingActiveAdmin(c.env, user.id))) {
    return c.redirect(accountFlow("profile", "delete-account", { notice: "last_active_admin" }))
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
