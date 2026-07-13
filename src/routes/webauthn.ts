import type { Context } from "hono"
import { Hono } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import {
  buildAuthenticationOptions,
  buildRegistrationOptions,
  verifyAndStoreRegistration,
  verifyAuthentication,
} from "../auth/passkey"
import { createSession } from "../auth/session"
import { SESSION_TTL, TOKEN_TTL } from "../config"
import { getUserById } from "../db/queries/users"
import { recordAudit } from "../security/audit"
import { setSessionCookie } from "../security/cookies"
import { verifyCsrfToken } from "../security/csrf"
import { checkIpRateLimit, isWebAuthnCeremonyId } from "../security/ingress"
import { checkRateLimit } from "../security/rate-limit"
import { createReauthContinuation } from "../security/reauth-continuation"
import { hasRecentAuthentication } from "../security/recent-auth"
import { clientIpHash, userAgentHash } from "../security/request-meta"
import { safeLocalPath } from "../security/return-to"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AppBindings } from "../types/app"
import type { WebAuthnChallengePayload } from "../types/tokens"
import { readJsonBody } from "../utils/http"
import { randomToken } from "../utils/random"

export const webauthn = new Hono<AppBindings>()

const CEREMONY_COOKIE = "__Host-keyforge_webauthn"
const PASSKEY_RATE_LIMIT = 20
const PASSKEY_VERIFY_RATE_LIMIT = 40
const PASSKEY_RATE_WINDOW_SECONDS = 5 * 60
const PASSKEY_REAUTHENTICATION_URL = "/login?reauth=1&return_to=%2F%3Fsection%3Dpasskeys"

function recentAuthenticationRequired(c: Context<AppBindings>): Response {
  return c.json(
    {
      error: "recent_authentication_required",
      reauthenticate_url: PASSKEY_REAUTHENTICATION_URL,
    },
    403,
  )
}

async function storeChallenge(
  c: Context<AppBindings>,
  payload: WebAuthnChallengePayload,
): Promise<void> {
  const ceremonyId = randomToken(16)
  await c.env.WEBAUTHN_CHALLENGE.getByName(await hashOpaqueToken(ceremonyId)).store(
    payload,
    TOKEN_TTL.webauthnChallenge,
  )
  setCookie(c, CEREMONY_COOKIE, ceremonyId, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: TOKEN_TTL.webauthnChallenge,
  })
}

async function consumeChallenge(c: Context<AppBindings>): Promise<WebAuthnChallengePayload | null> {
  const ceremonyId = getCookie(c, CEREMONY_COOKIE)
  deleteCookie(c, CEREMONY_COOKIE, { path: "/", secure: true })
  if (ceremonyId === undefined || !isWebAuthnCeremonyId(ceremonyId)) {
    return null
  }
  const result = await c.env.WEBAUTHN_CHALLENGE.getByName(
    await hashOpaqueToken(ceremonyId),
  ).consume()
  return result.found ? result.value : null
}

webauthn.post("/webauthn/register/options", async (c) => {
  const user = c.get("user")
  if (user === undefined) {
    return c.json({ error: "unauthorized" }, 401)
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return recentAuthenticationRequired(c)
  }
  if (!verifyCsrfToken(c, c.req.header("x-keyforge-csrf"))) {
    return c.json({ error: "csrf_validation_failed" }, 403)
  }
  const options = await buildRegistrationOptions(c.env, user)
  await storeChallenge(c, { kind: "registration", challenge: options.challenge, userId: user.id })
  return c.json(options)
})

webauthn.post("/webauthn/register/verify", async (c) => {
  const user = c.get("user")
  if (user === undefined) {
    return c.json({ error: "unauthorized" }, 401)
  }
  if (!hasRecentAuthentication(c.get("session"))) {
    return recentAuthenticationRequired(c)
  }
  if (!verifyCsrfToken(c, c.req.header("x-keyforge-csrf"))) {
    return c.json({ error: "csrf_validation_failed" }, 403)
  }
  const challenge = await consumeChallenge(c)
  if (challenge === null || challenge.kind !== "registration" || challenge.userId !== user.id) {
    return c.json({ verified: false, error: "invalid_challenge" }, 400)
  }
  const verified = await verifyAndStoreRegistration(
    c.env,
    user,
    await readJsonBody(c),
    challenge.challenge,
  )
  if (verified) {
    await recordAudit(c.env, {
      type: "user.passkey.updated",
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "passkey registered",
    })
  }
  return c.json({ verified }, verified ? 200 : 400)
})

webauthn.post("/webauthn/login/options", async (c) => {
  const ipHash = await clientIpHash(c)
  const rate = await checkRateLimit(
    c.env,
    `passkey:${ipHash ?? "unknown"}`,
    PASSKEY_RATE_LIMIT,
    PASSKEY_RATE_WINDOW_SECONDS,
  )
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    return c.json({ error: "rate_limited" }, 429)
  }
  const options = await buildAuthenticationOptions(c.env)
  await storeChallenge(c, { kind: "authentication", challenge: options.challenge, userId: null })
  return c.json(options)
})

webauthn.post("/webauthn/login/verify", async (c) => {
  const requestId = c.get("requestId")
  const rate = await checkIpRateLimit(
    c,
    "passkey-verify",
    PASSKEY_VERIFY_RATE_LIMIT,
    PASSKEY_RATE_WINDOW_SECONDS,
  )
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    return c.json({ error: "rate_limited" }, 429)
  }
  const challenge = await consumeChallenge(c)
  if (challenge === null || challenge.kind !== "authentication") {
    return c.json({ verified: false, error: "invalid_challenge" }, 400)
  }
  const body = await readJsonBody(c)
  const userId = await verifyAuthentication(c.env, body, challenge.challenge)
  const user = userId === null ? null : await getUserById(c.env, userId)
  if (user === null || user.disabled) {
    await recordAudit(c.env, {
      type: "user.login.passkey.failure",
      requestId,
      success: false,
      detail: "passkey authentication failed",
    })
    return c.json({ verified: false }, 400)
  }
  const session = await createSession(c.env, {
    userId: user.id,
    authMethod: "passkey",
    passkeyAuthenticated: true,
    ttlSeconds: SESSION_TTL.default,
    ipHash: await clientIpHash(c),
    userAgentHash: await userAgentHash(c),
  })
  setSessionCookie(c, session.token, SESSION_TTL.default)
  await recordAudit(c.env, {
    type: "user.login.passkey.success",
    userId: user.id,
    requestId,
    success: true,
  })
  const metadata =
    typeof body === "object" && body !== null
      ? (body as { returnTo?: unknown; reauthenticate?: unknown })
      : {}
  const returnTo = safeLocalPath(typeof metadata.returnTo === "string" ? metadata.returnTo : null)
  const redirectTo =
    metadata.reauthenticate === true
      ? await createReauthContinuation(c.env, session.sessionId, returnTo)
      : returnTo
  return c.json({ verified: true, redirect_to: redirectTo })
})
