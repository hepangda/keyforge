import { Hono } from "hono"
import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { HTTPException } from "hono/http-exception"
import { secureHeaders } from "hono/secure-headers"
import { deliverQueuedEmail, isQueuedEmailMessage } from "./email/sender"
import { AVATAR_UPLOAD_MAX_BODY_BYTES } from "./media/avatar"
import { avatarTooLargeResponse, isAvatarUploadPath } from "./media/avatar-http"
import { i18nMiddleware } from "./middleware/i18n"
import { sessionMiddleware } from "./middleware/session"
import { runScheduledMaintenance } from "./operations/maintenance"
import { account } from "./routes/account"
import { accountSecurity } from "./routes/account-security"
import { admin } from "./routes/admin"
import { assets } from "./routes/assets"
import { authorize } from "./routes/authorize"
import { avatars } from "./routes/avatars"
import { bootstrap } from "./routes/bootstrap"
import { adminConsole } from "./routes/console"
import { device } from "./routes/device"
import { health } from "./routes/health"
import { home } from "./routes/home"
import { language } from "./routes/language"
import { login } from "./routes/login"
import { magicLink } from "./routes/magic-link"
import { oauth } from "./routes/oauth"
import { recovery } from "./routes/recovery"
import { webauthn } from "./routes/webauthn"
import { wellKnown } from "./routes/well-known"
import { insertAuditBatch, recordAudit } from "./security/audit"
import { AppError, OAuthError } from "./security/errors"
import type { AppBindings } from "./types/app"
import { renderErrorPage } from "./views/consent"

const app = new Hono<AppBindings>()

// Most endpoints handle small form or JSON bodies. Avatar uploads carry image
// bytes and need a much larger ceiling, so the limit is chosen per request:
// registering two `bodyLimit` middlewares would not work, because both match
// and the stricter one still applies.
const DEFAULT_MAX_BODY_BYTES = 256 * 1024
const strictBodyLimit = bodyLimit({
  maxSize: DEFAULT_MAX_BODY_BYTES,
  onError: (c) => c.json({ error: "payload_too_large" }, 413),
})
const avatarBodyLimit = bodyLimit({
  maxSize: AVATAR_UPLOAD_MAX_BODY_BYTES,
  onError: (c) => avatarTooLargeResponse(c),
})

app.use("*", async (c, next) => {
  const limit = isAvatarUploadPath(new URL(c.req.url).pathname) ? avatarBodyLimit : strictBodyLimit
  return await limit(c, next)
})

// Correlate every request; echo the id back for tracing.
app.use("*", async (c, next) => {
  const requestId = c.req.header("cf-ray") ?? crypto.randomUUID()
  c.set("requestId", requestId)
  await next()
  c.header("x-request-id", requestId)
})

app.use("*", i18nMiddleware)

// Relying parties embed the `picture` claim URL straight into an `<img>`, and
// an image is a no-CORS subresource: the browser enforces
// Cross-Origin-Resource-Policy on it, not CORS. The global `same-origin`
// policy set by `secureHeaders` below therefore blocks every relying party
// from rendering the avatar it was just handed. Registered ahead of
// `secureHeaders` so this override runs after it on the way out.
app.use("/avatars/*", async (c, next) => {
  await next()
  c.header("cross-origin-resource-policy", "cross-origin")
})

// OAuth login and consent forms post to this origin before redirecting to a
// client's registered callback. Browsers apply form-action to that full
// redirect chain, so those pages must allow their one validated callback
// source. Keep every other page at the stricter self-only default.
app.use("*", async (c, next) => {
  await next()
  const redirectSource = c.get("oauthRedirectFormAction")
  if (redirectSource === undefined) return

  const policy = c.res.headers.get("content-security-policy")
  if (policy === null) return
  c.header(
    "content-security-policy",
    policy.replace("form-action 'self';", `form-action 'self' ${redirectSource};`),
  )
})

app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'none'"],
      baseUri: ["'none'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      // `blob:` lets the avatar uploader preview the resized image it produced
      // locally, before any bytes leave the browser.
      imgSrc: ["'self'", "https:", "data:", "blob:"],
      objectSrc: ["'none'"],
      // Cloudflare automatically injects a versioned Web Analytics beacon
      // below /beacon.min.js/. Keep the documented unversioned URL too so the
      // policy also supports manual injection without trusting the whole host.
      scriptSrc: [
        "'self'",
        "https://static.cloudflareinsights.com/beacon.min.js",
        "https://static.cloudflareinsights.com/beacon.min.js/",
      ],
      styleSrc: ["'unsafe-inline'"],
      workerSrc: ["'none'"],
    },
    permissionsPolicy: {
      camera: [],
      geolocation: [],
      microphone: [],
      payment: [],
      usb: [],
    },
    xFrameOptions: "DENY",
  }),
)

// Identity and administration responses carry personal data, CSRF values, or
// one-time capabilities. Public metadata/assets opt into their own policy.
app.use("*", async (c, next) => {
  await next()
  const path = new URL(c.req.url).pathname
  // Avatars are keyed by an unguessable, content-specific object key, so they
  // carry no session data and are safe to cache publicly.
  if (
    !path.startsWith("/assets/") &&
    !path.startsWith("/.well-known/") &&
    !path.startsWith("/avatars/")
  ) {
    c.header("cache-control", "no-store")
    c.header("pragma", "no-cache")
  }
})

// Public OIDC metadata is safe to read cross-origin.
app.use("/.well-known/*", cors({ origin: "*", allowMethods: ["GET"] }))

// Relying parties embed the `picture` claim URL directly, so avatars must be
// readable from any origin.
app.use("/avatars/*", cors({ origin: "*", allowMethods: ["GET"] }))

// OAuth API endpoints are cookie-free and authenticate with PKCE, client
// credentials, or bearer tokens. Wildcard CORS enables browser public clients
// without granting ambient account-session authority.
for (const path of [
  "/oauth/token",
  "/oauth/userinfo",
  "/oauth/revoke",
  "/oauth/introspect",
  "/oauth/device_authorization",
]) {
  app.use(
    path,
    cors({
      origin: "*",
      allowMethods: ["GET", "POST", "OPTIONS"],
      allowHeaders: ["Authorization", "Content-Type"],
      maxAge: 600,
    }),
  )
}

app.use("*", sessionMiddleware)

app.route("/", health)
app.route("/", assets)
app.route("/", avatars)
app.route("/", language)
app.route("/", wellKnown)
app.route("/", bootstrap)
app.route("/", oauth)
app.route("/", authorize)
app.route("/", device)
app.route("/", magicLink)
app.route("/", recovery)
app.route("/", webauthn)
app.route("/", admin)
app.route("/", adminConsole)
app.route("/", account)
app.route("/", accountSecurity)
app.route("/", login)
app.route("/", home)

function acceptsHtml(c: { req: { header(name: string): string | undefined } }): boolean {
  return c.req.header("accept")?.includes("text/html") === true
}

app.notFound((c) =>
  acceptsHtml(c)
    ? c.html(renderErrorPage(c.get("i18n"), "The requested page was not found."), 404)
    : c.json({ error: "not_found" }, 404),
)

app.onError(async (err, c) => {
  const requestId = c.get("requestId")
  if (err instanceof HTTPException) {
    return err.getResponse()
  }
  if (err instanceof OAuthError) {
    if (err.code !== "authorization_pending" && err.code !== "slow_down") {
      console.error("error.oauth", requestId, err.code, err.detail ?? err.message)
    }
    const headers: Record<string, string> = { "cache-control": "no-store" }
    if (err.code === "invalid_client" && err.status === 401) {
      headers["www-authenticate"] = 'Basic realm="oauth", error="invalid_client"'
    }
    if (err.code === "invalid_client") {
      try {
        await recordAudit(c.env, {
          type: "security.invalid_client",
          requestId,
          success: false,
          detail: err.detail ?? err.message,
        })
      } catch (auditError) {
        console.error("audit.security_error_failed", requestId, auditError)
      }
    }
    return Response.json(err.toBody(), {
      status: err.status,
      headers,
    })
  }
  if (err instanceof AppError) {
    console.error("error.app", requestId, err.status, err.detail ?? err.message)
    if (acceptsHtml(c)) {
      return c.html(renderErrorPage(c.get("i18n"), err.publicMessage), err.status as 400)
    }
    return Response.json({ error: err.publicMessage }, { status: err.status })
  }
  console.error("error.unhandled", requestId, err)
  if (acceptsHtml(c)) {
    return c.html(renderErrorPage(c.get("i18n"), "Something went wrong. Please try again."), 500)
  }
  return Response.json(
    { error: "server_error", error_description: "Internal server error" },
    { status: 500 },
  )
})

export default {
  fetch: app.fetch,
  async queue(batch, env): Promise<void> {
    const emailJobs: unknown[] = []
    const auditEvents: unknown[] = []
    for (const message of batch.messages) {
      if (isQueuedEmailMessage(message.body)) emailJobs.push(message.body)
      else auditEvents.push(message.body)
    }
    await Promise.all(emailJobs.map((message) => deliverQueuedEmail(env, message)))
    await insertAuditBatch(env, auditEvents)
  },
  async scheduled(controller, env): Promise<void> {
    const result = await runScheduledMaintenance(env, Math.floor(controller.scheduledTime / 1000))
    console.log("maintenance.completed", controller.cron, result)
  },
} satisfies ExportedHandler<Env>

export { AuthorizationCodeDO } from "./do/AuthorizationCodeDO"
export { OneTimeTokenDO } from "./do/OneTimeTokenDO"
export { RateLimitDO } from "./do/RateLimitDO"
export { RefreshTokenFamilyDO } from "./do/RefreshTokenFamilyDO"
export { WebAuthnChallengeDO } from "./do/WebAuthnChallengeDO"
