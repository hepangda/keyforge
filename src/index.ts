import { Hono } from "hono"
import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { HTTPException } from "hono/http-exception"
import { secureHeaders } from "hono/secure-headers"
import { deliverQueuedEmail, isQueuedEmailMessage } from "./email/sender"
import { i18nMiddleware } from "./middleware/i18n"
import { sessionMiddleware } from "./middleware/session"
import { runScheduledMaintenance } from "./operations/maintenance"
import { account } from "./routes/account"
import { accountSecurity } from "./routes/account-security"
import { admin } from "./routes/admin"
import { assets } from "./routes/assets"
import { authorize } from "./routes/authorize"
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

app.use(
  "*",
  bodyLimit({
    maxSize: 256 * 1024,
    onError: (c) => c.json({ error: "payload_too_large" }, 413),
  }),
)

// Correlate every request; echo the id back for tracing.
app.use("*", async (c, next) => {
  const requestId = c.req.header("cf-ray") ?? crypto.randomUUID()
  c.set("requestId", requestId)
  await next()
  c.header("x-request-id", requestId)
})

app.use("*", i18nMiddleware)

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
      imgSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
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
  if (!path.startsWith("/assets/") && !path.startsWith("/.well-known/")) {
    c.header("cache-control", "no-store")
    c.header("pragma", "no-cache")
  }
})

// Public OIDC metadata is safe to read cross-origin.
app.use("/.well-known/*", cors({ origin: "*", allowMethods: ["GET"] }))

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
