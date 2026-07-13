import type { Context } from "hono"
import { DEVICE_CODE_GRANT, DEVICE_POLL_INTERVAL_SECONDS, TOKEN_TTL } from "../config"
import { createDeviceSession } from "../db/queries/devices"
import { recordAudit } from "../security/audit"
import { OAuthError } from "../security/errors"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"
import { generateUserCode, randomToken } from "../utils/random"
import { nowSeconds } from "../utils/time"
import { resolveResourceForScopes } from "./resources"
import { parseScopeString, serializeScopes, validateRequestedScopes } from "./scopes"
import { normalizeUserCode } from "./user-code"

export async function handleDeviceAuthorization(
  c: Context<AppBindings>,
  client: OAuthClient,
  form: URLSearchParams,
): Promise<Response> {
  const clientId = client.clientId
  if (!client.allowedGrantTypes.includes(DEVICE_CODE_GRANT)) {
    throw new OAuthError("unauthorized_client", {
      description: "Client may not use the device flow",
      detail: `device_code grant not allowed for ${clientId}`,
    })
  }

  const requested = parseScopeString(form.get("scope"))
  const scopes =
    requested.length > 0
      ? validateRequestedScopes(requested, client.allowedScopes)
      : [...client.allowedScopes]
  const resource = await resolveResourceForScopes(c.env, client, form.get("resource"), scopes)
  const scope = serializeScopes(scopes)

  const deviceCode = randomToken(32)
  const userCode = generateUserCode()
  const expiresAt = nowSeconds() + TOKEN_TTL.deviceCode
  const created = await createDeviceSession(c.env, {
    deviceCodeHash: await hashOpaqueToken(deviceCode),
    userCodeHash: await hashOpaqueToken(normalizeUserCode(userCode)),
    clientId,
    resourceUri: resource,
    scope,
    expiresAt,
    pollIntervalSeconds: DEVICE_POLL_INTERVAL_SECONDS,
    // A high global breaker protects storage without letting one or two IPs
    // exhaust a public client's capacity; ordinary abuse is limited per IP.
    maxActiveSessions: client.type === "confidential" ? 250 : 1_000,
  })
  if (!created) {
    throw new OAuthError("temporarily_unavailable", {
      status: 429,
      description: "Too many active device authorization requests",
      detail: `active device authorization cap exceeded for ${clientId}`,
    })
  }
  await recordAudit(c.env, {
    type: "oauth.device.started",
    clientId,
    resourceUri: resource,
    scope,
    requestId: c.get("requestId"),
    success: true,
  })

  const verificationUri = `${c.env.ISSUER}/device`
  return c.json(
    {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(userCode)}`,
      expires_in: TOKEN_TTL.deviceCode,
      interval: DEVICE_POLL_INTERVAL_SECONDS,
    },
    200,
    { "cache-control": "no-store" },
  )
}
