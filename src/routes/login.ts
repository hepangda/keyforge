import type { Context } from "hono"
import { Hono } from "hono"
import { decodeProtectedHeader } from "jose"
import { verifyLoginPassword } from "../auth/password"
import { createSession, revokeSessionByToken } from "../auth/session"
import { JWT_TYP, SESSION_TTL } from "../config"
import { getClientById } from "../db/queries/clients"
import { getUserByLogin } from "../db/queries/users"
import { isSafePostLogoutRedirectUri } from "../oauth/post-logout"
import { buildRedirectUrl, formActionSource, isRegisteredRedirectUri } from "../oauth/redirect"
import { validateOAuthParameterSet } from "../oauth/request-limits"
import { recordAudit } from "../security/audit"
import { clearSessionCookie, getSessionCookie, setSessionCookie } from "../security/cookies"
import { issueCsrfToken, verifyCsrfToken } from "../security/csrf"
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
import { verifyHistoricalJwt } from "../tokens/jwt"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import { renderErrorPage } from "../views/consent"
import {
  renderEndSessionConfirmation,
  renderLoginPage,
  renderLogoutConfirmation,
} from "../views/login"

export const login = new Hono<AppBindings>()

const LOGIN_RATE_LIMIT = 10
const LOGIN_IP_RATE_LIMIT = 50
const LOGIN_RATE_WINDOW_SECONDS = 300
const GENERIC_LOGIN_ERROR = "Invalid email, username, or password."

async function allowRegisteredOAuthCallback(
  c: Context<AppBindings>,
  returnTo: string,
): Promise<void> {
  const requestUrl = new URL(c.req.url)
  const authorizationUrl = new URL(returnTo, requestUrl.origin)
  if (
    authorizationUrl.origin !== requestUrl.origin ||
    authorizationUrl.pathname !== "/oauth/authorize" ||
    validateOAuthParameterSet(authorizationUrl.searchParams) !== null ||
    authorizationUrl.searchParams.getAll("client_id").length !== 1 ||
    authorizationUrl.searchParams.getAll("redirect_uri").length !== 1
  ) {
    return
  }

  const clientId = authorizationUrl.searchParams.get("client_id")
  const redirectUri = authorizationUrl.searchParams.get("redirect_uri")
  if (clientId === null || redirectUri === null) return

  const client = await getClientById(c.env, clientId)
  if (
    client === null ||
    !client.enabled ||
    !client.allowedGrantTypes.includes("authorization_code") ||
    !isRegisteredRedirectUri(client, redirectUri)
  ) {
    return
  }

  c.set("oauthRedirectFormAction", formActionSource(redirectUri))
}

login.get("/login", async (c) => {
  const reauthenticating = c.req.query("reauth") === "1"
  const returnTo = safeLocalPath(c.req.query("return_to") ?? null)
  if (c.get("user") !== undefined && !reauthenticating) {
    return c.redirect(returnTo)
  }
  await allowRegisteredOAuthCallback(c, returnTo)
  const csrfToken = issueCsrfToken(c)
  const notice = c.req.query("notice")
  const error = notice === "account_deleted" ? "Your account has been deleted." : undefined
  return c.html(
    renderLoginPage({
      i18n: c.get("i18n"),
      csrfToken,
      returnTo,
      reauthenticating,
      ...(error === undefined ? {} : { error }),
    }),
  )
})

login.post("/login", async (c) => {
  const form = await c.req.raw.formData()
  const identifier = readFormField(form, "email").trim()
  const displayIdentifier = identifier.length <= EMAIL_INPUT_MAX_LENGTH ? identifier : ""
  const password = readFormField(form, "password")
  const returnTo = safeLocalPath(readFormField(form, "return_to") || null)
  await allowRegisteredOAuthCallback(c, returnTo)
  const reauthenticating = readFormField(form, "reauth") === "1"
  const requestId = c.get("requestId")
  const ipHash = await clientIpHash(c)

  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(
      renderLoginPage({
        i18n: c.get("i18n"),
        csrfToken: issueCsrfToken(c),
        returnTo,
        email: displayIdentifier,
        error: GENERIC_LOGIN_ERROR,
        reauthenticating,
      }),
      403,
    )
  }

  const ipRate = await checkRateLimit(
    c.env,
    `login:ip:${ipHash ?? "unknown"}`,
    LOGIN_IP_RATE_LIMIT,
    LOGIN_RATE_WINDOW_SECONDS,
  )
  if (!ipRate.allowed) {
    if (shouldAuditRateLimit(ipRate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        requestId,
        ipHash,
        success: false,
        detail: "login rate limit exceeded",
      })
    }
    c.header("retry-after", String(ipRate.retryAfterSeconds))
    return c.html(
      renderLoginPage({
        i18n: c.get("i18n"),
        csrfToken: issueCsrfToken(c),
        returnTo,
        email: displayIdentifier,
        error: "Too many attempts. Please wait and try again.",
        reauthenticating,
      }),
      429,
    )
  }

  const accountHash = await requestCorrelationHash(
    c.env,
    "login-account",
    emailCorrelationValue(identifier),
  )
  const [ipAccountRate, accountRate] = await Promise.all([
    checkRateLimit(
      c.env,
      `login:ip-account:${ipHash ?? "unknown"}:${accountHash}`,
      LOGIN_RATE_LIMIT,
      LOGIN_RATE_WINDOW_SECONDS,
    ),
    checkRateLimit(c.env, `login:account:${accountHash}`, 30, 15 * 60),
  ])
  if (!ipAccountRate.allowed || !accountRate.allowed) {
    if (shouldAuditRateLimit(ipAccountRate, accountRate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        requestId,
        ipHash,
        success: false,
        detail: "login rate limit exceeded",
      })
    }
    c.header(
      "retry-after",
      String(Math.max(ipAccountRate.retryAfterSeconds, accountRate.retryAfterSeconds)),
    )
    return c.html(
      renderLoginPage({
        i18n: c.get("i18n"),
        csrfToken: issueCsrfToken(c),
        returnTo,
        email: displayIdentifier,
        error: "Too many attempts. Please wait and try again.",
        reauthenticating,
      }),
      429,
    )
  }

  const user =
    identifier.length <= EMAIL_INPUT_MAX_LENGTH ? await getUserByLogin(c.env, identifier) : null
  const passwordValid = await verifyLoginPassword(c.env, user?.id ?? null, password)
  if (user === null || user.disabled || !passwordValid) {
    await recordAudit(c.env, {
      type: "user.login.password.failure",
      requestId,
      ipHash,
      userId: user?.id ?? null,
      success: false,
      detail: "password login failed",
    })
    return c.html(
      renderLoginPage({
        i18n: c.get("i18n"),
        csrfToken: issueCsrfToken(c),
        returnTo,
        email: displayIdentifier,
        error: GENERIC_LOGIN_ERROR,
        reauthenticating,
      }),
      401,
    )
  }

  await Promise.all([
    c.env.RATE_LIMIT.getByName(`login:ip-account:${ipHash ?? "unknown"}:${accountHash}`).reset(),
    c.env.RATE_LIMIT.getByName(`login:account:${accountHash}`).reset(),
  ])

  const session = await createSession(c.env, {
    userId: user.id,
    authMethod: "password",
    ttlSeconds: SESSION_TTL.default,
    ipHash,
    userAgentHash: await userAgentHash(c),
  })
  setSessionCookie(c, session.token, SESSION_TTL.default)
  await recordAudit(c.env, {
    type: "user.login.password.success",
    userId: user.id,
    requestId,
    ipHash,
    success: true,
  })
  return c.redirect(
    reauthenticating
      ? await createReauthContinuation(c.env, session.sessionId, returnTo)
      : returnTo,
  )
})

login.get("/logout", (c) => {
  if (c.get("user") === undefined) {
    return c.redirect("/login")
  }
  return c.html(renderLogoutConfirmation(c.get("i18n"), issueCsrfToken(c)))
})

login.post("/logout", async (c) => {
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.json({ error: "csrf_validation_failed" }, 403)
  }
  const token = getSessionCookie(c)
  const user = c.get("user")
  if (token !== undefined) {
    await revokeSessionByToken(c.env, token)
  }
  clearSessionCookie(c)
  if (user !== undefined) {
    await recordAudit(c.env, {
      type: "user.logout",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
    })
  }
  if (readFormField(form, "intent") === "switch_account") {
    const continueTo = safeLocalPath(readFormField(form, "continue_to") || null)
    return c.redirect(`/login?return_to=${encodeURIComponent(continueTo)}`)
  }
  return c.redirect("/login")
})

login.get("/oauth/end_session", async (c) => {
  const params = new URL(c.req.url).searchParams
  return endSession(c, params, false)
})

login.post("/oauth/end_session", async (c) => {
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.json({ error: "csrf_validation_failed" }, 403)
  }
  const params = new URLSearchParams()
  for (const name of ["id_token_hint", "client_id", "post_logout_redirect_uri", "state"]) {
    const value = readFormField(form, name)
    if (value !== "") {
      params.set(name, value)
    }
  }
  return endSession(c, params, true)
})

async function endSession(
  c: Context<AppBindings>,
  params: URLSearchParams,
  confirmed: boolean,
): Promise<Response> {
  c.header("cache-control", "no-store")
  if (validateOAuthParameterSet(params) !== null) {
    return c.html(
      renderErrorPage(c.get("i18n"), "The logout request contains invalid parameters."),
      400,
    )
  }
  const association = await resolveLogoutClient(c.env, params)
  if (association.kind === "error") {
    return c.html(renderErrorPage(c.get("i18n"), association.description), 400)
  }

  const postLogoutRedirectUri = params.get("post_logout_redirect_uri")
  if (postLogoutRedirectUri !== null) {
    if (
      association.client === null ||
      !association.client.postLogoutRedirectUris.includes(postLogoutRedirectUri) ||
      !isSafePostLogoutRedirectUri(postLogoutRedirectUri)
    ) {
      return c.html(renderErrorPage(c.get("i18n"), "Invalid post_logout_redirect_uri."), 400)
    }
  }

  const token = getSessionCookie(c)
  const user = c.get("user")
  if (
    association.hintedSubject !== null &&
    user !== undefined &&
    association.hintedSubject !== user.id
  ) {
    return c.html(
      renderErrorPage(c.get("i18n"), "id_token_hint does not belong to this session."),
      400,
    )
  }

  // A GET may validate and render, but never revokes a browser session. This
  // prevents cross-site image/link navigation from logging a user out.
  if (!confirmed && (token !== undefined || user !== undefined)) {
    return c.html(
      renderEndSessionConfirmation(
        c.get("i18n"),
        issueCsrfToken(c),
        params,
        association.client?.name ?? null,
      ),
    )
  }
  if (token !== undefined) {
    await revokeSessionByToken(c.env, token)
  }
  clearSessionCookie(c)
  if (user !== undefined) {
    await recordAudit(c.env, {
      type: "user.logout",
      userId: user.id,
      clientId: association.client?.clientId ?? null,
      requestId: c.get("requestId"),
      success: true,
      detail: "RP-Initiated Logout",
    })
  }

  if (postLogoutRedirectUri === null) {
    return c.redirect("/login")
  }
  const state = params.get("state")
  return c.redirect(
    state === null ? postLogoutRedirectUri : buildRedirectUrl(postLogoutRedirectUri, { state }),
  )
}

type LogoutClientResolution =
  | {
      readonly kind: "ok"
      readonly client: Awaited<ReturnType<typeof getClientById>>
      readonly hintedSubject: string | null
    }
  | { readonly kind: "error"; readonly description: string }

async function resolveLogoutClient(
  env: Env,
  params: URLSearchParams,
): Promise<LogoutClientResolution> {
  const requestedClientId = params.get("client_id")
  const hint = params.get("id_token_hint")
  let hintedClientId: string | null = null
  let hintedSubject: string | null = null

  if (hint !== null) {
    try {
      if (decodeProtectedHeader(hint).typ !== JWT_TYP.idToken) throw new Error("wrong token type")
      const payload = await verifyHistoricalJwt(env, hint)
      if (typeof payload.sub !== "string" || payload.sub === "") {
        return { kind: "error", description: "Invalid id_token_hint." }
      }
      hintedSubject = payload.sub
      const audiences =
        typeof payload.aud === "string"
          ? [payload.aud]
          : Array.isArray(payload.aud)
            ? payload.aud
            : []
      if (requestedClientId !== null) {
        if (!audiences.includes(requestedClientId)) {
          return { kind: "error", description: "client_id does not match id_token_hint." }
        }
        hintedClientId = requestedClientId
      } else if (audiences.length === 1) {
        hintedClientId = audiences[0] ?? null
      } else {
        return { kind: "error", description: "id_token_hint has an ambiguous audience." }
      }
    } catch {
      // An RP may send an expired ID token hint. If an explicit client_id is
      // also supplied, its registered redirect remains a sufficient, safe
      // association; otherwise the unverifiable hint cannot select a client.
      if (requestedClientId === null) {
        return { kind: "error", description: "Invalid id_token_hint." }
      }
      hintedClientId = requestedClientId
      hintedSubject = null
    }
  }

  const clientId = requestedClientId ?? hintedClientId
  if (clientId === null) {
    if (params.get("post_logout_redirect_uri") !== null) {
      return {
        kind: "error",
        description: "client_id or a valid id_token_hint is required for redirect.",
      }
    }
    return { kind: "ok", client: null, hintedSubject }
  }
  const client = await getClientById(env, clientId)
  return client === null
    ? { kind: "error", description: "Unknown logout client." }
    : { kind: "ok", client, hintedSubject }
}
