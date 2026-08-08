import type { Context } from "hono"
import { Hono } from "hono"
import { DEVICE_CODE_GRANT } from "../config"
import { getClientById } from "../db/queries/clients"
import {
  approveDeviceWithConsent,
  type DeviceSession,
  denyDevice,
  getDeviceByUserCodeHash,
} from "../db/queries/devices"
import { resolveResourceForScopes } from "../oauth/resources"
import { parseScopeString } from "../oauth/scopes"
import { normalizeUserCode } from "../oauth/user-code"
import { evaluateUserTokenAccess } from "../oauth/user-token-policy"
import { recordAudit } from "../security/audit"
import { issueCsrfToken, verifyCsrfToken } from "../security/csrf"
import { hasRecentAuthentication } from "../security/recent-auth"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AppBindings } from "../types/app"
import type { SessionRecord, User } from "../types/domain"
import { readFormField } from "../utils/form"
import { isExpired } from "../utils/time"
import {
  renderDeviceCodeEntryPage,
  renderDeviceConfirmPage,
  renderDeviceResultPage,
} from "../views/device"

export const device = new Hono<AppBindings>()

async function currentDeviceClient(env: Env, session: DeviceSession) {
  const client = await getClientById(env, session.clientId)
  if (
    client === null ||
    !client.enabled ||
    !client.allowedGrantTypes.includes(DEVICE_CODE_GRANT) ||
    session.resourceUri === null
  ) {
    return null
  }
  try {
    const resource = await resolveResourceForScopes(
      env,
      client,
      session.resourceUri,
      parseScopeString(session.scope),
    )
    return resource === session.resourceUri ? client : null
  } catch {
    return null
  }
}
type DeviceBrowserContext = { readonly user: User; readonly session: SessionRecord }

function deviceBrowserContext(
  c: Context<AppBindings>,
  normalizedUserCode: string,
): DeviceBrowserContext | Response {
  const user = c.get("user")
  const session = c.get("session")
  const returnTo =
    normalizedUserCode === ""
      ? "/device"
      : `/device?user_code=${encodeURIComponent(normalizedUserCode)}`
  if (user === undefined || session === undefined) {
    return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`)
  }
  if (!hasRecentAuthentication(session)) {
    const params = new URLSearchParams({
      reauth: "1",
      hint: "authorize_device",
      return_to: returnTo,
    })
    return c.redirect(`/login?${params.toString()}`)
  }
  return { user, session }
}

device.get("/device", async (c) => {
  const userCode = normalizeUserCode(c.req.query("user_code") ?? "")
  const browser = deviceBrowserContext(c, userCode)
  if (browser instanceof Response) return browser
  if (userCode === "") {
    return c.html(renderDeviceCodeEntryPage(c.get("i18n")))
  }
  const { user } = browser
  const session = await getDeviceByUserCodeHash(c.env, await hashOpaqueToken(userCode))
  if (session === null || session.status !== "pending" || isExpired(session.expiresAt)) {
    return c.html(
      renderDeviceCodeEntryPage(c.get("i18n"), "That code is invalid or has expired.", userCode),
      400,
    )
  }
  const client = await currentDeviceClient(c.env, session)
  if (client === null) {
    return c.html(
      renderDeviceCodeEntryPage(
        c.get("i18n"),
        "That authorization request is no longer available.",
        userCode,
      ),
      400,
    )
  }
  const access = await evaluateUserTokenAccess(c.env, {
    userId: user.id,
    clientId: client.clientId,
    resourceUri: session.resourceUri ?? "",
    scopes: parseScopeString(session.scope),
  })
  if (!access.allowed) {
    return c.html(
      renderDeviceCodeEntryPage(
        c.get("i18n"),
        "This account cannot grant the requested access.",
        userCode,
      ),
      403,
    )
  }
  return c.html(
    renderDeviceConfirmPage({
      i18n: c.get("i18n"),
      csrfToken: issueCsrfToken(c),
      userCode,
      clientName: client.name,
      scopes: parseScopeString(session.scope),
      resource: session.resourceUri ?? "",
    }),
  )
})

device.post("/device/confirm", async (c) => {
  const form = await c.req.raw.formData()
  const userCode = normalizeUserCode(readFormField(form, "user_code"))
  const browser = deviceBrowserContext(c, userCode)
  if (browser instanceof Response) return browser
  const { user, session: browserSession } = browser
  if (!verifyCsrfToken(c, readFormField(form, "csrf_token") || undefined)) {
    return c.html(
      renderDeviceCodeEntryPage(c.get("i18n"), "Your session expired. Please try again.", userCode),
      403,
    )
  }
  const session = await getDeviceByUserCodeHash(c.env, await hashOpaqueToken(userCode))
  if (session === null || session.status !== "pending" || isExpired(session.expiresAt)) {
    return c.html(
      renderDeviceCodeEntryPage(c.get("i18n"), "That code is invalid or has expired.", userCode),
      400,
    )
  }
  const scopes = parseScopeString(session.scope)
  const client = await currentDeviceClient(c.env, session)
  if (client === null) {
    return c.html(
      renderDeviceCodeEntryPage(
        c.get("i18n"),
        "That authorization request is no longer available.",
        userCode,
      ),
      400,
    )
  }
  const access = await evaluateUserTokenAccess(c.env, {
    userId: user.id,
    clientId: client.clientId,
    resourceUri: session.resourceUri ?? "",
    scopes,
  })
  if (!access.allowed) {
    return c.html(
      renderDeviceCodeEntryPage(
        c.get("i18n"),
        "This account cannot grant the requested access.",
        userCode,
      ),
      403,
    )
  }
  if (readFormField(form, "decision") === "approve") {
    if (session.resourceUri === null) {
      return c.html(
        renderDeviceCodeEntryPage(c.get("i18n"), "That request has no valid resource.", userCode),
        400,
      )
    }
    const approved = await approveDeviceWithConsent(c.env, {
      id: session.id,
      userId: user.id,
      sessionId: browserSession.id,
      authTime: browserSession.authTime,
      clientId: session.clientId,
      scope: session.scope,
      resource: session.resourceUri,
    })
    if (!approved) {
      return c.html(
        renderDeviceCodeEntryPage(c.get("i18n"), "That request was already handled.", userCode),
        409,
      )
    }
    await recordAudit(c.env, {
      type: "oauth.device.approved",
      userId: user.id,
      clientId: session.clientId,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.html(renderDeviceResultPage(c.get("i18n"), "approved"))
  }
  if (!(await denyDevice(c.env, session.id))) {
    return c.html(
      renderDeviceCodeEntryPage(c.get("i18n"), "That request was already handled.", userCode),
      409,
    )
  }
  await recordAudit(c.env, {
    type: "oauth.device.denied",
    userId: user.id,
    clientId: session.clientId,
    requestId: c.get("requestId"),
    success: false,
  })
  return c.html(renderDeviceResultPage(c.get("i18n"), "denied"))
})
