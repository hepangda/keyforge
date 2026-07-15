import type { Context } from "hono"
import { Hono } from "hono"
import { saveConsent } from "../db/queries/consents"
import type { AuthorizeParams, AuthorizeValidation } from "../oauth/authorize"
import { issueAuthorizationCode, validateAuthorizeRequest } from "../oauth/authorize"
import { consentCoversScopes } from "../oauth/consent"
import { buildRedirectUrl } from "../oauth/redirect"
import { validateOAuthParameterSet } from "../oauth/request-limits"
import { serializeScopes } from "../oauth/scopes"
import { userMayReceiveScopes } from "../oauth/user-scope-policy"
import { recordAudit } from "../security/audit"
import { issueCsrfToken, verifyCsrfToken } from "../security/csrf"
import { consumeReauthContinuation } from "../security/reauth-continuation"
import type { AppBindings } from "../types/app"
import type { SessionRecord, User } from "../types/domain"
import { assertNever } from "../utils/assert"
import { readFormField } from "../utils/form"
import { nowSeconds } from "../utils/time"
import { renderConsentPage, renderErrorPage } from "../views/consent"

export const authorize = new Hono<AppBindings>()

const AUTHORIZE_PARAM_KEYS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "resource",
  "prompt",
  "max_age",
] as const

type ConsentContext = { readonly user: User; readonly session: SessionRecord }
type HiddenFields = Readonly<Record<string, string>>

function withState(params: Record<string, string>, state: string | null): Record<string, string> {
  return state === null ? params : { ...params, state }
}

authorize.get("/oauth/authorize", async (c) => {
  const requestUrl = new URL(c.req.url)
  if (validateOAuthParameterSet(requestUrl.searchParams) !== null) {
    return c.html(
      renderErrorPage(
        c.get("i18n"),
        "The authorization request contains invalid or oversized parameters.",
      ),
      400,
    )
  }
  const url = await consumeReauthContinuation(c.env, c.get("session")?.id, requestUrl)
  const validation = await validateAuthorizeRequest(c.env, url.searchParams)
  return dispatchValidation(c, validation, collectHiddenFields(url.searchParams))
})

authorize.post("/oauth/authorize/decision", async (c) => {
  const user = c.get("user")
  const session = c.get("session")
  if (user === undefined || session === undefined) {
    return c.redirect("/login")
  }
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(renderErrorPage(c.get("i18n"), "Your session expired. Please try again."), 403)
  }
  const query = new URLSearchParams()
  for (const key of AUTHORIZE_PARAM_KEYS) {
    const value = readFormField(form, key)
    if (value !== "") {
      query.set(key, value)
    }
  }
  const validation = await validateAuthorizeRequest(c.env, query)
  if (validation.kind !== "ok") {
    return dispatchValidation(c, validation, {})
  }
  const params = validation.params
  const sessionTooOld =
    params.maxAge !== null &&
    (params.maxAge === 0 || Math.max(0, nowSeconds() - session.authTime) > params.maxAge)
  if (params.prompts.includes("login") || sessionTooOld) {
    return interactionError(c, params, "login_required", "Fresh user authentication is required")
  }
  if (!(await userMayReceiveScopes(c.env, user.id, params.scopes))) {
    return interactionError(
      c,
      params,
      "access_denied",
      "This account is not permitted to grant the requested privileged scopes",
    )
  }
  if (params.prompts.includes("none")) {
    return interactionError(c, params, "consent_required", "Interactive consent is required")
  }
  if (readFormField(form, "decision") !== "approve") {
    return denyAuthorization(c, params, { user, session })
  }
  await saveConsent(c.env, {
    userId: user.id,
    clientId: params.clientId,
    scope: serializeScopes(params.scopes),
    resource: params.resource,
  })
  return completeAuthorization(c, params, { user, session })
})

async function dispatchValidation(
  c: Context<AppBindings>,
  validation: AuthorizeValidation,
  hiddenFields: HiddenFields,
): Promise<Response> {
  switch (validation.kind) {
    case "invalid_request_page": {
      if (validation.reason === "invalid_client" || validation.reason === "invalid_redirect_uri") {
        await recordAudit(c.env, {
          type:
            validation.reason === "invalid_client"
              ? "security.invalid_client"
              : "security.invalid_redirect_uri",
          clientId: validation.clientId,
          requestId: c.get("requestId"),
          success: false,
          detail: validation.description,
        })
      }
      return c.html(renderErrorPage(c.get("i18n"), validation.description), 400)
    }
    case "error_redirect":
      return errorRedirect(c, validation)
    case "ok":
      return handleAuthorized(c, validation.params, hiddenFields)
    default:
      return assertNever(validation)
  }
}

async function errorRedirect(
  c: Context<AppBindings>,
  validation: Extract<AuthorizeValidation, { kind: "error_redirect" }>,
): Promise<Response> {
  await recordAudit(c.env, {
    type: "oauth.authorize.denied",
    requestId: c.get("requestId"),
    success: false,
    detail: `${validation.error}: ${validation.description}`,
  })
  const params = withState(
    { error: validation.error, error_description: validation.description },
    validation.state,
  )
  return c.redirect(buildRedirectUrl(validation.redirectUri, params))
}

async function handleAuthorized(
  c: Context<AppBindings>,
  params: AuthorizeParams,
  hiddenFields: HiddenFields,
): Promise<Response> {
  const user = c.get("user")
  const session = c.get("session")
  const noInteraction = params.prompts.includes("none")
  if (user === undefined || session === undefined) {
    if (noInteraction) {
      return interactionError(c, params, "login_required", "User authentication is required")
    }
    return redirectToLogin(c, params.prompts.includes("login") || params.maxAge !== null)
  }
  const sessionTooOld =
    params.maxAge !== null &&
    (params.maxAge === 0 || Math.max(0, nowSeconds() - session.authTime) > params.maxAge)
  if (params.prompts.includes("login") || sessionTooOld) {
    if (noInteraction) {
      return interactionError(c, params, "login_required", "Fresh user authentication is required")
    }
    return redirectToLogin(c, true)
  }
  if (!(await userMayReceiveScopes(c.env, user.id, params.scopes))) {
    return interactionError(
      c,
      params,
      "access_denied",
      "This account is not permitted to grant the requested privileged scopes",
    )
  }
  await recordAudit(c.env, {
    type: "oauth.authorize.started",
    userId: user.id,
    clientId: params.clientId,
    resourceUri: params.resource,
    scope: serializeScopes(params.scopes),
    requestId: c.get("requestId"),
    success: true,
  })
  const hasConsent = await consentCoversScopes(
    c.env,
    user.id,
    params.clientId,
    params.resource,
    params.scopes,
  )
  if (hasConsent && !params.prompts.includes("consent")) {
    return completeAuthorization(c, params, { user, session })
  }
  if (noInteraction) {
    return interactionError(c, params, "consent_required", "User consent is required")
  }
  return c.html(
    renderConsentPage({
      i18n: c.get("i18n"),
      csrfToken: issueCsrfToken(c),
      clientName: params.client.name,
      scopes: params.scopes,
      resource: params.resource,
      hiddenFields,
    }),
  )
}

function redirectToLogin(c: Context<AppBindings>, forceReauthentication: boolean): Response {
  const url = new URL(c.req.url)
  // Interaction requirements remain intact until a new session presents the
  // one-time continuation proof minted by the login completion path.
  url.searchParams.delete("_keyforge_reauth")
  const returnTo = `${url.pathname}${url.search}`
  const loginParams = new URLSearchParams({ return_to: returnTo })
  if (forceReauthentication) {
    loginParams.set("reauth", "1")
  }
  return c.redirect(`/login?${loginParams.toString()}`)
}

async function interactionError(
  c: Context<AppBindings>,
  params: AuthorizeParams,
  error: "login_required" | "consent_required" | "access_denied",
  description: string,
): Promise<Response> {
  await recordAudit(c.env, {
    type: "oauth.authorize.denied",
    userId: c.get("user")?.id ?? null,
    clientId: params.clientId,
    resourceUri: params.resource,
    scope: serializeScopes(params.scopes),
    requestId: c.get("requestId"),
    success: false,
    detail: `${error}: ${description}`,
  })
  return c.redirect(
    buildRedirectUrl(
      params.redirectUri,
      withState({ error, error_description: description }, params.state),
    ),
  )
}

async function completeAuthorization(
  c: Context<AppBindings>,
  params: AuthorizeParams,
  ctx: ConsentContext,
): Promise<Response> {
  const code = await issueAuthorizationCode(c.env, params, {
    user: ctx.user,
    sessionId: ctx.session.id,
    authTime: ctx.session.authTime,
  })
  await recordAudit(c.env, {
    type: "oauth.authorize.completed",
    userId: ctx.user.id,
    clientId: params.clientId,
    resourceUri: params.resource,
    scope: serializeScopes(params.scopes),
    requestId: c.get("requestId"),
    success: true,
  })
  return c.redirect(buildRedirectUrl(params.redirectUri, withState({ code }, params.state)))
}

async function denyAuthorization(
  c: Context<AppBindings>,
  params: AuthorizeParams,
  ctx: ConsentContext,
): Promise<Response> {
  await recordAudit(c.env, {
    type: "oauth.authorize.denied",
    userId: ctx.user.id,
    clientId: params.clientId,
    requestId: c.get("requestId"),
    success: false,
    detail: "user denied consent",
  })
  return c.redirect(
    buildRedirectUrl(
      params.redirectUri,
      withState(
        { error: "access_denied", error_description: "The user denied the request" },
        params.state,
      ),
    ),
  )
}

function collectHiddenFields(query: URLSearchParams): HiddenFields {
  const fields: Record<string, string> = {}
  for (const key of AUTHORIZE_PARAM_KEYS) {
    const value = query.get(key)
    if (value !== null) {
      fields[key] = value
    }
  }
  return fields
}
