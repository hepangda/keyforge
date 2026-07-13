import type { Context } from "hono"
import { Hono } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import { z } from "zod"
import type { SocialLoginOutcome, SocialProviderId } from "../auth/account-linking"
import { resolveSocialLogin, SOCIAL_PROVIDERS } from "../auth/account-linking"
import { buildAuthorizeUrl, exchangeCode, fetchSocialProfile } from "../auth/oauth-providers"
import { createSession } from "../auth/session"
import { SESSION_TTL } from "../config"
import { getUserById } from "../db/queries/users"
import { computeS256Challenge } from "../oauth/pkce"
import { getRuntimeConfig } from "../operations/runtime-config"
import { recordAudit } from "../security/audit"
import { setSessionCookie } from "../security/cookies"
import { verifyCsrfToken } from "../security/csrf"
import { checkIpRateLimit, isAccountCapabilityToken } from "../security/ingress"
import { shouldAuditRateLimit } from "../security/rate-limit"
import { createReauthContinuation } from "../security/reauth-continuation"
import { hasRecentAuthentication } from "../security/recent-auth"
import { clientIpHash, userAgentHash } from "../security/request-meta"
import { safeLocalPath } from "../security/return-to"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AppBindings } from "../types/app"
import type { SocialStatePayload } from "../types/tokens"
import { readFormField } from "../utils/form"
import { randomToken } from "../utils/random"
import { renderErrorPage } from "../views/consent"

export const social = new Hono<AppBindings>()

const STATE_COOKIE = "__Host-keyforge_social"
const SOCIAL_STATE_TTL_SECONDS = 10 * 60
const SOCIAL_BEGIN_RATE_LIMIT = 30
const SOCIAL_CALLBACK_RATE_LIMIT = 60

const stateSchema = z.object({
  purpose: z.literal("social_state"),
  provider: z.enum(SOCIAL_PROVIDERS),
  verifier: z.string(),
  returnTo: z.string(),
  linkUserId: z.string().nullable(),
  linkSessionId: z.string().nullable(),
  reauthenticate: z.boolean(),
})

function toProvider(value: string): SocialProviderId | null {
  return SOCIAL_PROVIDERS.find((provider) => provider === value) ?? null
}

async function beginSocialFlow(
  c: Context<AppBindings>,
  provider: SocialProviderId,
  returnTo: string,
  linkUserId: string | null,
  reauthenticate = false,
): Promise<Response> {
  const rate = await checkIpRateLimit(c, "social-begin", SOCIAL_BEGIN_RATE_LIMIT)
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    if (shouldAuditRateLimit(rate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        requestId: c.get("requestId"),
        success: false,
        detail: "social login start rate limit exceeded",
      })
    }
    return c.html(renderErrorPage("Too many attempts. Please wait and try again."), 429)
  }
  const state = randomToken(32)
  const verifier = randomToken(32)
  const redirectUri = `${c.env.ISSUER}/login/${provider}/callback`
  const authorizeUrl = buildAuthorizeUrl(c.env, provider, {
    redirectUri,
    state,
    codeChallenge: await computeS256Challenge(verifier),
  })
  if (authorizeUrl === null) {
    return c.html(renderErrorPage(`Sign-in with ${provider} is not configured.`), 503)
  }
  const linkSessionId = linkUserId === null ? null : (c.get("session")?.id ?? null)
  if (linkUserId !== null && linkSessionId === null) {
    return c.html(renderErrorPage("Your account session is unavailable."), 403)
  }
  const payload: SocialStatePayload = {
    purpose: "social_state",
    provider,
    verifier,
    returnTo,
    linkUserId,
    linkSessionId,
    reauthenticate,
  }
  await c.env.ONE_TIME_TOKEN.getByName(await hashOpaqueToken(state)).store(
    payload,
    SOCIAL_STATE_TTL_SECONDS,
  )
  setCookie(c, STATE_COOKIE, state, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: SOCIAL_STATE_TTL_SECONDS,
  })
  return c.redirect(authorizeUrl)
}

social.get("/login/:provider", async (c) => {
  const provider = toProvider(c.req.param("provider"))
  if (provider === null) {
    return c.notFound()
  }
  if (c.get("user") !== undefined && c.req.query("reauth") !== "1") {
    return c.redirect("/?section=identities&notice=use_connect")
  }
  return beginSocialFlow(
    c,
    provider,
    safeLocalPath(c.req.query("return_to") ?? null),
    null,
    c.req.query("reauth") === "1",
  )
})

social.post("/account/identities/:provider/connect", async (c) => {
  const provider = toProvider(c.req.param("provider"))
  const user = c.get("user")
  if (provider === null) {
    return c.notFound()
  }
  if (user === undefined) {
    return c.redirect("/login?return_to=%2F%3Fsection%3Didentities")
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return c.redirect("/login?reauth=1&return_to=%2F%3Fsection%3Didentities")
  }
  const form = await c.req.raw.formData()
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.redirect("/?section=identities&notice=invalid")
  }
  return beginSocialFlow(c, provider, "/?section=identities&notice=identity_linked", user.id)
})

social.get("/login/:provider/callback", async (c) => {
  const provider = toProvider(c.req.param("provider"))
  if (provider === null) {
    return c.notFound()
  }
  const cookie = getCookie(c, STATE_COOKIE)
  const code = c.req.query("code")
  const state = c.req.query("state")
  if (
    cookie === undefined ||
    code === undefined ||
    state === undefined ||
    cookie !== state ||
    !isAccountCapabilityToken(cookie)
  ) {
    deleteCookie(c, STATE_COOKIE, { path: "/", secure: true })
    return c.html(renderErrorPage("The sign-in request could not be verified."), 400)
  }
  const rate = await checkIpRateLimit(c, "capability:social", SOCIAL_CALLBACK_RATE_LIMIT)
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    return c.html(renderErrorPage("Too many attempts. Please wait and try again."), 429)
  }
  const consumed = await c.env.ONE_TIME_TOKEN.getByName(await hashOpaqueToken(cookie)).consume()
  deleteCookie(c, STATE_COOKIE, { path: "/", secure: true })
  const parsed = consumed.found ? stateSchema.safeParse(consumed.value) : null
  const saved = parsed?.success === true ? parsed.data : null
  if (saved === null || saved.provider !== provider) {
    return c.html(renderErrorPage("The sign-in request could not be verified."), 400)
  }

  if (saved.linkUserId !== null) {
    const currentSession = c.get("session")
    if (
      saved.linkSessionId === null ||
      currentSession?.id !== saved.linkSessionId ||
      c.get("user")?.id !== saved.linkUserId ||
      !hasRecentAuthentication(currentSession)
    ) {
      return c.html(renderErrorPage("Your account session changed before linking completed."), 403)
    }
  }

  const accessToken = await exchangeCode(c.env, provider, {
    code,
    redirectUri: `${c.env.ISSUER}/login/${provider}/callback`,
    codeVerifier: saved.verifier,
  })
  if (accessToken === null) {
    return c.html(renderErrorPage("Sign-in with the provider failed."), 502)
  }
  const profile = await fetchSocialProfile(provider, accessToken)
  const outcome = await resolveSocialLogin(
    c.env,
    profile,
    saved.linkUserId,
    getRuntimeConfig(c.env).allowSelfSignup,
  )
  return applyOutcome(
    c,
    provider,
    outcome,
    saved.returnTo,
    saved.linkUserId !== null,
    saved.reauthenticate,
  )
})

async function applyOutcome(
  c: Context<AppBindings>,
  provider: SocialProviderId,
  outcome: SocialLoginOutcome,
  returnTo: string,
  linking: boolean,
  reauthenticate: boolean,
): Promise<Response> {
  if (outcome.kind === "conflict") {
    await recordAudit(c.env, {
      type: `user.login.${provider}.failure`,
      userId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: false,
      detail: "provider identity is already connected to another account",
    })
    return c.redirect("/?section=identities&notice=identity_conflict")
  }
  if (outcome.kind === "binding_required") {
    await recordAudit(c.env, {
      type: `user.login.${provider}.failure`,
      requestId: c.get("requestId"),
      success: false,
      detail: "provider email already exists locally; explicit binding required",
    })
    return c.redirect("/login?error=account_exists")
  }
  if (outcome.kind === "signup_disabled") {
    await recordAudit(c.env, {
      type: `user.login.${provider}.failure`,
      requestId: c.get("requestId"),
      success: false,
      detail: "social account is not provisioned and self-signup is disabled",
    })
    return c.redirect("/login?error=signup_disabled")
  }
  if (linking && outcome.kind === "linked") {
    await recordAudit(c.env, {
      type: `user.login.${provider}.success`,
      userId: outcome.userId,
      requestId: c.get("requestId"),
      success: true,
      detail: "provider identity linked",
    })
    return c.redirect(safeLocalPath(returnTo))
  }
  const loginUser = await getUserById(c.env, outcome.userId)
  if (loginUser === null || loginUser.disabled) {
    await recordAudit(c.env, {
      type: `user.login.${provider}.failure`,
      userId: outcome.userId,
      requestId: c.get("requestId"),
      success: false,
      detail: "provider account belongs to an unavailable local user",
    })
    return c.html(renderErrorPage("This account is unavailable."), 403)
  }
  const session = await createSession(c.env, {
    userId: outcome.userId,
    authMethod: provider,
    ttlSeconds: SESSION_TTL.default,
    ipHash: await clientIpHash(c),
    userAgentHash: await userAgentHash(c),
  })
  setSessionCookie(c, session.token, SESSION_TTL.default)
  await recordAudit(c.env, {
    type: `user.login.${provider}.success`,
    userId: outcome.userId,
    requestId: c.get("requestId"),
    success: true,
  })
  const safeReturnTo = safeLocalPath(returnTo)
  return c.redirect(
    reauthenticate
      ? await createReauthContinuation(c.env, session.sessionId, safeReturnTo)
      : safeReturnTo,
  )
}
