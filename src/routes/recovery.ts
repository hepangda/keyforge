import type { Context } from "hono"
import { Hono } from "hono"
import {
  consumeEmailChangeToken,
  consumeEmailVerificationToken,
  consumePasswordResetToken,
  createPasswordResetToken,
  peekEmailChangeToken,
  peekEmailVerificationToken,
  peekPasswordResetToken,
} from "../auth/account-tokens"
import { setUserPasswordAtSecurityVersion } from "../auth/password"
import { getUserByEmail, getUserById, updateUser, updateUserEmail } from "../db/queries/users"
import { enqueueEmail } from "../email/sender"
import { passwordResetEmail } from "../email/templates"
import { recordAudit } from "../security/audit"
import { issueCsrfToken, verifyCsrfToken } from "../security/csrf"
import { checkIpRateLimit, isAccountCapabilityToken } from "../security/ingress"
import { checkRateLimit, shouldAuditRateLimit } from "../security/rate-limit"
import {
  clientIpHash,
  EMAIL_INPUT_MAX_LENGTH,
  emailCorrelationValue,
  requestCorrelationHash,
} from "../security/request-meta"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import {
  renderPasswordResetForm,
  renderPasswordResetRequest,
  renderPasswordResetSent,
  renderRecoveryConfirmation,
  renderRecoveryResult,
} from "../views/recovery"

export const recovery = new Hono<AppBindings>()

const RESET_RATE_LIMIT = 5
const RESET_RATE_WINDOW_SECONDS = 15 * 60
const RECOVERY_CAPABILITY_RATE_LIMIT = 60

async function enforceRecoveryCapabilityRate(c: Context<AppBindings>): Promise<Response | null> {
  const rate = await checkIpRateLimit(
    c,
    "capability:account-recovery",
    RECOVERY_CAPABILITY_RATE_LIMIT,
  )
  if (rate.allowed) return null
  c.header("retry-after", String(rate.retryAfterSeconds))
  return c.html(
    renderRecoveryResult(
      "Recovery temporarily unavailable",
      "Too many attempts. Please wait and try again.",
      false,
    ),
    429,
  )
}

recovery.get("/password/forgot", (c) => c.html(renderPasswordResetRequest(issueCsrfToken(c))))

recovery.post("/password/forgot", async (c) => {
  const form = await c.req.raw.formData()
  const email = readFormField(form, "email").trim().toLowerCase()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(renderPasswordResetRequest(issueCsrfToken(c), "Please try again."), 403)
  }
  const ipHash = await clientIpHash(c)
  const requestId = c.get("requestId")
  const displayEmail = email.length <= EMAIL_INPUT_MAX_LENGTH ? email : ""
  const ipRate = await checkRateLimit(
    c.env,
    `password-reset:ip:${ipHash ?? "unknown"}`,
    RESET_RATE_LIMIT * 3,
    RESET_RATE_WINDOW_SECONDS,
  )
  if (!ipRate.allowed) {
    if (shouldAuditRateLimit(ipRate)) {
      c.executionCtx.waitUntil(
        recordAudit(c.env, {
          type: "security.rate_limited",
          requestId,
          ipHash,
          success: false,
          detail: "password reset rate limit exceeded",
        }),
      )
    }
    return c.html(renderPasswordResetSent(displayEmail))
  }
  const addressHash = await requestCorrelationHash(
    c.env,
    "password-reset-address",
    emailCorrelationValue(email),
  )
  const addressRate = await checkRateLimit(
    c.env,
    `password-reset:address:${addressHash}`,
    RESET_RATE_LIMIT,
    RESET_RATE_WINDOW_SECONDS,
  )
  if (addressRate.allowed) {
    c.executionCtx.waitUntil(
      (async () => {
        const user =
          email.length <= EMAIL_INPUT_MAX_LENGTH ? await getUserByEmail(c.env, email) : null
        await recordAudit(c.env, {
          type: "user.password.reset.requested",
          userId: user?.id ?? null,
          requestId,
          ipHash,
          success: true,
          detail: "password reset requested",
        })
        if (user !== null && !user.disabled) {
          try {
            const { url } = await createPasswordResetToken(c.env, user.id, user.email)
            await enqueueEmail(c.env, { to: user.email, ...passwordResetEmail(url) })
          } catch (error) {
            console.error("email.password_reset_failed", requestId, error)
          }
        }
      })(),
    )
  } else if (shouldAuditRateLimit(addressRate)) {
    c.executionCtx.waitUntil(
      recordAudit(c.env, {
        type: "security.rate_limited",
        requestId,
        ipHash,
        success: false,
        detail: "password reset rate limit exceeded",
      }),
    )
  }
  return c.html(renderPasswordResetSent(displayEmail))
})

recovery.get("/password/reset", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const limited = await enforceRecoveryCapabilityRate(c)
  if (limited !== null) return limited
  const payload = await peekPasswordResetToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  return c.html(
    renderPasswordResetForm(
      issueCsrfToken(c),
      token,
      undefined,
      payload.purpose === "account_invitation",
    ),
  )
})

recovery.post("/password/reset", async (c) => {
  const form = await c.req.raw.formData()
  const token = readFormField(form, "token")
  const password = readFormField(form, "password")
  const confirmation = readFormField(form, "password_confirm")
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(renderPasswordResetForm(issueCsrfToken(c), token, "Please try again."), 403)
  }
  if (password.length < 12 || password.length > 128 || password !== confirmation) {
    return c.html(
      renderPasswordResetForm(
        issueCsrfToken(c),
        token,
        "Passwords must match and contain 12 to 128 characters.",
      ),
      400,
    )
  }
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const resetLimited = await enforceRecoveryCapabilityRate(c)
  if (resetLimited !== null) return resetLimited
  const payload = await consumePasswordResetToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const user = await getUserById(c.env, payload.userId)
  if (user === null || user.disabled || user.email !== payload.email) {
    return c.html(
      renderRecoveryResult("Account unavailable", "This account is unavailable.", false),
      400,
    )
  }
  if (
    !(await setUserPasswordAtSecurityVersion(c.env, user.id, password, payload.securityVersion, {
      verifyEmail: payload.purpose === "account_invitation",
    }))
  ) {
    return c.html(
      renderRecoveryResult(
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  await recordAudit(c.env, {
    type: "user.password.reset.completed",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.html(
    renderRecoveryResult(
      payload.purpose === "account_invitation" ? "Invitation accepted" : "Password reset",
      payload.purpose === "account_invitation"
        ? "Your account is active and ready to use."
        : "Your new password is ready to use.",
      true,
    ),
  )
})

recovery.get("/account/email/verify", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const limited = await enforceRecoveryCapabilityRate(c)
  if (limited !== null) return limited
  const payload = await peekEmailVerificationToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  return c.html(
    renderRecoveryConfirmation({
      title: "Verify your email",
      message: `Confirm ${payload.email} as your account email address.`,
      action: "/account/email/verify",
      token,
      csrfToken: issueCsrfToken(c),
      submitLabel: "Verify email",
    }),
  )
})

recovery.post("/account/email/verify", async (c) => {
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(renderRecoveryResult("Verification unavailable", "Please try again.", false), 403)
  }
  const token = readFormField(form, "token")
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const verificationLimited = await enforceRecoveryCapabilityRate(c)
  if (verificationLimited !== null) return verificationLimited
  const payload = await consumeEmailVerificationToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const user = await getUserById(c.env, payload.userId)
  if (user === null || user.email !== payload.email) {
    return c.html(
      renderRecoveryResult("Account unavailable", "This account is unavailable.", false),
      400,
    )
  }
  await updateUser(c.env, user.id, { emailVerified: true })
  await recordAudit(c.env, {
    type: "user.email.verified",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.html(renderRecoveryResult("Email verified", "Your email address is now verified.", true))
})

recovery.get("/account/email/change/verify", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const limited = await enforceRecoveryCapabilityRate(c)
  if (limited !== null) return limited
  const payload = await peekEmailChangeToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  return c.html(
    renderRecoveryConfirmation({
      title: "Confirm email change",
      message: `Change your account email to ${payload.email}. This signs out every session.`,
      action: "/account/email/change/verify",
      token,
      csrfToken: issueCsrfToken(c),
      submitLabel: "Change email",
    }),
  )
})

recovery.post("/account/email/change/verify", async (c) => {
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(renderRecoveryResult("Email change unavailable", "Please try again.", false), 403)
  }
  const token = readFormField(form, "token")
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const changeLimited = await enforceRecoveryCapabilityRate(c)
  if (changeLimited !== null) return changeLimited
  const payload = await consumeEmailChangeToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
      ),
      400,
    )
  }
  const currentUser = await getUserById(c.env, payload.userId)
  if (currentUser === null || currentUser.disabled) {
    return c.html(
      renderRecoveryResult("Account unavailable", "This account is unavailable.", false),
      400,
    )
  }
  const result = await updateUserEmail(
    c.env,
    payload.userId,
    payload.email,
    payload.securityVersion,
  )
  if (result !== "updated") {
    return c.html(
      renderRecoveryResult(
        "Email change unavailable",
        result === "conflict"
          ? "That email address is already in use."
          : "This account is unavailable.",
        false,
      ),
      result === "conflict" ? 409 : 400,
    )
  }
  await recordAudit(c.env, {
    type: "user.email.changed",
    userId: payload.userId,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.html(
    renderRecoveryResult(
      "Email address changed",
      "Your new email is confirmed. Sign in again to continue.",
      true,
    ),
  )
})
