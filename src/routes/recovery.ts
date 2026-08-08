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
import {
  minimumPasswordLength,
  PASSWORD_POLICY,
  setUserPasswordAtSecurityVersion,
} from "../auth/password"
import {
  getUserByEmail,
  getUserById,
  isUserAdmin,
  updateUser,
  updateUserEmail,
} from "../db/queries/users"
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
import { safeLocalPath } from "../security/return-to"
import type { AppBindings } from "../types/app"
import type { AccountOneTimeTokenPayload } from "../types/tokens"
import { readFormField } from "../utils/form"
import { continuationHref } from "../views/layout"
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
const PASSWORD_RESET_START = "/password/forgot"
const EMAIL_CHANGE_RETURN_TO = "/?section=profile&flow=change-email"

function resetContinuation(
  payload: AccountOneTimeTokenPayload,
  destination: "/login" | "/password/forgot",
): string {
  return continuationHref(
    destination,
    safeLocalPath(payload.redirectTo),
    payload.reauthenticate === true,
  )
}

async function enforceRecoveryCapabilityRate(
  c: Context<AppBindings>,
  actionHref: string,
  actionLabel: string,
): Promise<Response | null> {
  const rate = await checkIpRateLimit(
    c,
    "capability:account-recovery",
    RECOVERY_CAPABILITY_RATE_LIMIT,
  )
  if (rate.allowed) return null
  c.header("retry-after", String(rate.retryAfterSeconds))
  return c.html(
    renderRecoveryResult(
      c.get("i18n"),
      "Recovery temporarily unavailable",
      "Too many attempts. Please wait and try again.",
      false,
      actionHref,
      actionLabel,
    ),
    429,
  )
}

recovery.get("/password/forgot", (c) => {
  const returnTo = safeLocalPath(c.req.query("return_to") ?? null)
  return c.html(
    renderPasswordResetRequest(
      c.get("i18n"),
      issueCsrfToken(c),
      returnTo,
      c.req.query("reauth") === "1",
      undefined,
      "",
      c.req.query("hint"),
    ),
  )
})

recovery.post("/password/forgot", async (c) => {
  const form = await c.req.raw.formData()
  const email = readFormField(form, "email").trim().toLowerCase()
  const returnTo = safeLocalPath(readFormField(form, "return_to") || null)
  const reauthenticating = readFormField(form, "reauth") === "1"
  const rawHint = readFormField(form, "hint")
  const hint = rawHint === "" ? undefined : rawHint
  const displayEmail = email.length <= EMAIL_INPUT_MAX_LENGTH ? email : ""
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(
      renderPasswordResetRequest(
        c.get("i18n"),
        issueCsrfToken(c),
        returnTo,
        reauthenticating,
        "Please try again.",
        displayEmail,
        hint,
      ),
      403,
    )
  }
  const ipHash = await clientIpHash(c)
  const requestId = c.get("requestId")

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
    return c.html(
      renderPasswordResetSent(c.get("i18n"), displayEmail, returnTo, reauthenticating, hint),
    )
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
            const { url } = await createPasswordResetToken(c.env, user.id, user.email, {
              redirectTo: returnTo,
              reauthenticate: reauthenticating,
              purpose: "password_reset",
            })
            await enqueueEmail(c.env, {
              to: user.email,
              ...passwordResetEmail(url, c.get("i18n").locale),
            })
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
  return c.html(
    renderPasswordResetSent(c.get("i18n"), displayEmail, returnTo, reauthenticating, hint),
  )
})

recovery.get("/password/reset", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
        PASSWORD_RESET_START,
        "Request a new reset link",
      ),
      400,
    )
  }
  const limited = await enforceRecoveryCapabilityRate(
    c,
    PASSWORD_RESET_START,
    "Request a new reset link",
  )
  if (limited !== null) return limited
  const payload = await peekPasswordResetToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
        PASSWORD_RESET_START,
        "Request a new reset link",
      ),
      400,
    )
  }
  const user = await getUserById(c.env, payload.userId)
  if (user === null || user.disabled) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Account unavailable",
        "This account is unavailable.",
        false,
        resetContinuation(payload, "/password/forgot"),
        "Request a new reset link",
      ),
      400,
    )
  }
  const minimum = minimumPasswordLength(await isUserAdmin(c.env, user.id))
  return c.html(
    renderPasswordResetForm(
      c.get("i18n"),
      issueCsrfToken(c),
      token,
      minimum,
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
    return c.html(
      renderPasswordResetForm(c.get("i18n"), issueCsrfToken(c), token, 6, "Please try again."),
      403,
    )
  }
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
        PASSWORD_RESET_START,
        "Request a new reset link",
      ),
      400,
    )
  }
  const resetLimited = await enforceRecoveryCapabilityRate(
    c,
    PASSWORD_RESET_START,
    "Request a new reset link",
  )
  if (resetLimited !== null) return resetLimited
  const pendingPayload = await peekPasswordResetToken(c.env, token)
  if (pendingPayload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
        PASSWORD_RESET_START,
        "Request a new reset link",
      ),
      400,
    )
  }
  const pendingUser = await getUserById(c.env, pendingPayload.userId)
  if (pendingUser === null || pendingUser.disabled || pendingUser.email !== pendingPayload.email) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Account unavailable",
        "This account is unavailable.",
        false,
        resetContinuation(pendingPayload, "/password/forgot"),
        "Request a new reset link",
      ),
      400,
    )
  }
  const minimum = minimumPasswordLength(await isUserAdmin(c.env, pendingUser.id))
  if (
    password.length < minimum ||
    password.length > PASSWORD_POLICY.maximum ||
    password !== confirmation
  ) {
    return c.html(
      renderPasswordResetForm(
        c.get("i18n"),
        issueCsrfToken(c),
        token,
        minimum,
        c.get("i18n").t("Passwords must match and contain {minimum} to {maximum} characters.", {
          minimum,
          maximum: PASSWORD_POLICY.maximum,
        }),
        pendingPayload.purpose === "account_invitation",
      ),
      400,
    )
  }
  const payload = await consumePasswordResetToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
        resetContinuation(pendingPayload, "/password/forgot"),
        "Request a new reset link",
      ),
      400,
    )
  }
  const user = await getUserById(c.env, payload.userId)
  if (user === null || user.disabled || user.email !== payload.email) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Account unavailable",
        "This account is unavailable.",
        false,
        resetContinuation(payload, "/password/forgot"),
        "Request a new reset link",
      ),
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
        c.get("i18n"),
        "Reset link unavailable",
        "This password reset link is invalid, expired, or already used.",
        false,
        resetContinuation(payload, "/password/forgot"),
        "Request a new reset link",
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
      c.get("i18n"),
      payload.purpose === "account_invitation" ? "Invitation accepted" : "Password reset",
      payload.purpose === "account_invitation"
        ? "Your account is active and ready to use."
        : "Your new password is ready to use.",
      true,
      resetContinuation(payload, "/login"),
      "Continue to sign in",
    ),
  )
})

recovery.get("/account/email/verify", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
        "/",
        "Back to your account",
      ),
      400,
    )
  }
  const limited = await enforceRecoveryCapabilityRate(c, "/", "Back to your account")
  if (limited !== null) return limited
  const payload = await peekEmailVerificationToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
        "/",
        "Back to your account",
      ),
      400,
    )
  }
  return c.html(
    renderRecoveryConfirmation({
      i18n: c.get("i18n"),
      title: "Verify your email",
      message: "Confirm {email} as your account email address.",
      messageValues: { email: payload.email },
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
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Verification unavailable",
        "Please try again.",
        false,
        "/",
        "Back to your account",
      ),
      403,
    )
  }
  const token = readFormField(form, "token")
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
        "/",
        "Back to your account",
      ),
      400,
    )
  }
  const verificationLimited = await enforceRecoveryCapabilityRate(c, "/", "Back to your account")
  if (verificationLimited !== null) return verificationLimited
  const payload = await consumeEmailVerificationToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Verification link unavailable",
        "This email verification link is invalid, expired, or already used.",
        false,
        "/",
        "Back to your account",
      ),
      400,
    )
  }
  const user = await getUserById(c.env, payload.userId)
  if (user === null || user.email !== payload.email) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Account unavailable",
        "This account is unavailable.",
        false,
        "/",
        "Back to your account",
      ),
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
  return c.html(
    renderRecoveryResult(
      c.get("i18n"),
      "Email verified",
      "Your email address is now verified.",
      true,
      "/",
      "Back to your account",
    ),
  )
})

recovery.get("/account/email/change/verify", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
      ),
      400,
    )
  }
  const limited = await enforceRecoveryCapabilityRate(
    c,
    EMAIL_CHANGE_RETURN_TO,
    "Back to your account",
  )
  if (limited !== null) return limited
  const payload = await peekEmailChangeToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
      ),
      400,
    )
  }
  return c.html(
    renderRecoveryConfirmation({
      i18n: c.get("i18n"),
      title: "Confirm email change",
      message: "Change your account email to {email}. This signs out every session.",
      messageValues: { email: payload.email },
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
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Email change unavailable",
        "Please try again.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
      ),
      403,
    )
  }
  const token = readFormField(form, "token")
  if (!isAccountCapabilityToken(token)) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
      ),
      400,
    )
  }
  const changeLimited = await enforceRecoveryCapabilityRate(
    c,
    EMAIL_CHANGE_RETURN_TO,
    "Back to your account",
  )
  if (changeLimited !== null) return changeLimited
  const payload = await consumeEmailChangeToken(c.env, token)
  if (payload === null) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Email change unavailable",
        "This email change link is invalid, expired, or already used.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
      ),
      400,
    )
  }
  const currentUser = await getUserById(c.env, payload.userId)
  if (currentUser === null || currentUser.disabled) {
    return c.html(
      renderRecoveryResult(
        c.get("i18n"),
        "Account unavailable",
        "This account is unavailable.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
      ),
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
        c.get("i18n"),
        "Email change unavailable",
        result === "conflict"
          ? "That email address is already in use."
          : "This account is unavailable.",
        false,
        EMAIL_CHANGE_RETURN_TO,
        "Back to your account",
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
      c.get("i18n"),
      "Email address changed",
      "Your new email is confirmed. Sign in again to continue.",
      true,
      "/login",
      "Continue to sign in",
    ),
  )
})
