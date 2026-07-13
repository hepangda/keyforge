import { Hono } from "hono"
import { consumeMagicLink, createMagicLink, peekMagicLink } from "../auth/magic-link"
import { createSessionAtSecurityVersion } from "../auth/session"
import { SESSION_TTL } from "../config"
import { getUserByEmail, getUserById, updateUser } from "../db/queries/users"
import { enqueueEmail } from "../email/sender"
import { magicLinkEmail } from "../email/templates"
import { recordAudit } from "../security/audit"
import { setSessionCookie } from "../security/cookies"
import { issueCsrfToken, verifyCsrfToken } from "../security/csrf"
import { checkIpRateLimit, isAccountCapabilityToken } from "../security/ingress"
import { checkRateLimit, shouldAuditRateLimit } from "../security/rate-limit"
import { createReauthContinuation } from "../security/reauth-continuation"
import {
  clientIpHash,
  EMAIL_INPUT_MAX_LENGTH,
  emailCorrelationValue,
  requestCorrelationHash,
  userAgentHash,
} from "../security/request-meta"
import { safeLocalPath } from "../security/return-to"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import { renderErrorPage } from "../views/consent"
import {
  renderMagicConfirmation,
  renderMagicRequestPage,
  renderMagicSentPage,
} from "../views/magic"

export const magicLink = new Hono<AppBindings>()

const MAGIC_RATE_LIMIT = 5
const MAGIC_RATE_WINDOW_SECONDS = 900
const MAGIC_CALLBACK_RATE_LIMIT = 60

magicLink.get("/login/magic", (c) =>
  c.html(
    renderMagicRequestPage(
      issueCsrfToken(c),
      safeLocalPath(c.req.query("return_to") ?? null),
      c.req.query("reauth") === "1",
    ),
  ),
)

magicLink.post("/login/magic", async (c) => {
  const form = await c.req.raw.formData()
  const email = readFormField(form, "email").toLowerCase()
  const returnTo = safeLocalPath(readFormField(form, "return_to") || null)
  const reauthenticating = readFormField(form, "reauth") === "1"
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(
      renderMagicRequestPage(issueCsrfToken(c), returnTo, reauthenticating, "Please try again."),
      403,
    )
  }

  const ipHash = await clientIpHash(c)
  const displayEmail = email.length <= EMAIL_INPUT_MAX_LENGTH ? email : ""
  const ipRate = await checkRateLimit(
    c.env,
    `magic:ip:${ipHash ?? "unknown"}`,
    MAGIC_RATE_LIMIT * 3,
    MAGIC_RATE_WINDOW_SECONDS,
  )
  if (!ipRate.allowed) {
    if (shouldAuditRateLimit(ipRate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        requestId: c.get("requestId"),
        ipHash,
        success: false,
        detail: "magic link rate limit exceeded",
      })
    }
    return c.html(renderMagicSentPage(displayEmail))
  }
  const addressHash = await requestCorrelationHash(
    c.env,
    "magic-address",
    emailCorrelationValue(email),
  )
  const addressRate = await checkRateLimit(
    c.env,
    `magic:address:${addressHash}`,
    MAGIC_RATE_LIMIT,
    MAGIC_RATE_WINDOW_SECONDS,
  )
  if (!addressRate.allowed) {
    if (shouldAuditRateLimit(addressRate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        requestId: c.get("requestId"),
        ipHash,
        success: false,
        detail: "magic link rate limit exceeded",
      })
    }
    return c.html(renderMagicSentPage(displayEmail))
  }

  const requestId = c.get("requestId")
  c.executionCtx.waitUntil(
    (async () => {
      await recordAudit(c.env, {
        type: "user.login.magic_link.requested",
        requestId,
        ipHash,
        success: true,
        detail: "magic link requested",
      })
      const user =
        email.length <= EMAIL_INPUT_MAX_LENGTH ? await getUserByEmail(c.env, email) : null
      if (user !== null && !user.disabled) {
        try {
          const { url } = await createMagicLink(c.env, {
            userId: user.id,
            email,
            redirectTo: returnTo,
            reauthenticate: reauthenticating,
          })
          await enqueueEmail(c.env, { to: email, ...magicLinkEmail(url) })
        } catch (error) {
          console.error("email.magic_link_failed", requestId, error)
        }
      }
    })(),
  )
  return c.html(renderMagicSentPage(displayEmail))
})

magicLink.get("/login/magic/callback", async (c) => {
  const token = c.req.query("token") ?? ""
  if (!isAccountCapabilityToken(token)) {
    return c.html(renderErrorPage("This sign-in link is invalid or has expired."), 400)
  }
  const rate = await checkIpRateLimit(c, "capability:magic", MAGIC_CALLBACK_RATE_LIMIT)
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    return c.html(renderErrorPage("Too many attempts. Please wait and try again."), 429)
  }
  const payload = await peekMagicLink(c.env, token)
  if (payload === null) {
    return c.html(renderErrorPage("This sign-in link is invalid or has expired."), 400)
  }
  return c.html(renderMagicConfirmation(issueCsrfToken(c), token, payload.email))
})

magicLink.post("/login/magic/callback", async (c) => {
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(renderErrorPage("This sign-in request could not be verified."), 403)
  }
  const token = readFormField(form, "token")
  if (!isAccountCapabilityToken(token)) {
    return c.html(renderErrorPage("This sign-in link is invalid or has expired."), 400)
  }
  const rate = await checkIpRateLimit(c, "capability:magic", MAGIC_CALLBACK_RATE_LIMIT)
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    return c.html(renderErrorPage("Too many attempts. Please wait and try again."), 429)
  }
  const payload = await consumeMagicLink(c.env, token)
  if (payload === null) {
    return c.html(renderErrorPage("This sign-in link is invalid or has expired."), 400)
  }
  const user = await getUserById(c.env, payload.userId)
  if (user === null || user.disabled || user.email !== payload.email) {
    return c.html(renderErrorPage("This account is unavailable."), 400)
  }
  if (!user.emailVerified) {
    await updateUser(c.env, user.id, { emailVerified: true })
  }
  const session = await createSessionAtSecurityVersion(
    c.env,
    {
      userId: user.id,
      authMethod: "magic_link",
      ttlSeconds: SESSION_TTL.default,
      ipHash: await clientIpHash(c),
      userAgentHash: await userAgentHash(c),
    },
    payload.securityVersion,
  )
  if (session === null) {
    return c.html(renderErrorPage("This sign-in link is invalid or has expired."), 400)
  }
  setSessionCookie(c, session.token, SESSION_TTL.default)
  await recordAudit(c.env, {
    type: "user.login.magic_link.consumed",
    userId: user.id,
    requestId: c.get("requestId"),
    success: true,
  })
  const returnTo = safeLocalPath(payload.redirectTo)
  return c.redirect(
    payload.reauthenticate === true
      ? await createReauthContinuation(c.env, session.sessionId, returnTo)
      : returnTo,
  )
})
