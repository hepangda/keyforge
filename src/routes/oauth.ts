import type { Context } from "hono"
import { Hono } from "hono"
import { DEVICE_CODE_GRANT } from "../config"
import { handleClientCredentials } from "../oauth/client-credentials"
import { authenticateClient } from "../oauth/clients"
import { handleDeviceAuthorization } from "../oauth/device-authorization"
import { handleIntrospect } from "../oauth/introspect"
import {
  OAUTH_FORM_MAX_BODY_BYTES,
  OAUTH_FORM_MAX_PARAMETERS,
  oauthParameterMaximumBytes,
  validateOAuthParameter,
} from "../oauth/request-limits"
import { handleRevoke } from "../oauth/revoke"
import { handleAuthorizationCode } from "../oauth/token/authorization-code"
import { handleDeviceCodeGrant } from "../oauth/token/device-code"
import { handleRefreshToken } from "../oauth/token/refresh-token"
import { handleUserInfo } from "../oauth/userinfo"
import { recordAudit } from "../security/audit"
import { OAuthError } from "../security/errors"
import { checkRateLimit, shouldAuditRateLimit } from "../security/rate-limit"
import { clientIpHash } from "../security/request-meta"
import type { AppBindings } from "../types/app"

export const oauth = new Hono<AppBindings>()

async function enforceOAuthRateLimit(
  c: Context<AppBindings>,
  key: string,
  limit: number,
  windowSeconds = 300,
): Promise<void> {
  const rate = await checkRateLimit(c.env, key, limit, windowSeconds)
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    if (shouldAuditRateLimit(rate)) {
      await recordAudit(c.env, {
        type: "security.rate_limited",
        requestId: c.get("requestId"),
        success: false,
        detail: `OAuth rate limit exceeded for ${key}`,
        metadata: { limit, window_seconds: windowSeconds },
      })
    }
    throw new OAuthError("temporarily_unavailable", {
      status: 429,
      description: "Too many requests",
      detail: `OAuth rate limit exceeded for ${key}`,
    })
  }
}

async function readFormBody(c: Context<AppBindings>): Promise<URLSearchParams> {
  const mediaType = c.req.header("content-type")?.split(";", 1)[0]?.trim().toLowerCase()
  if (mediaType !== "application/x-www-form-urlencoded") {
    throw new OAuthError("invalid_request", {
      description: "Content-Type must be application/x-www-form-urlencoded",
      detail: `unsupported OAuth request content type: ${mediaType ?? "missing"}`,
    })
  }
  const declaredLength = c.req.header("content-length")
  if (
    declaredLength !== undefined &&
    (!/^\d+$/.test(declaredLength) || Number(declaredLength) > OAUTH_FORM_MAX_BODY_BYTES)
  ) {
    throw new OAuthError("invalid_request", {
      description: "Request body is too large",
      detail: `OAuth form exceeded ${OAUTH_FORM_MAX_BODY_BYTES} bytes`,
    })
  }
  let bodyBytes: ArrayBuffer
  try {
    bodyBytes = await c.req.raw.arrayBuffer()
  } catch (error) {
    throw new OAuthError("invalid_request", {
      description: "Malformed form body",
      detail: "OAuth form body could not be parsed",
      cause: error,
    })
  }
  if (bodyBytes.byteLength > OAUTH_FORM_MAX_BODY_BYTES) {
    throw new OAuthError("invalid_request", {
      description: "Request body is too large",
      detail: `OAuth form exceeded ${OAUTH_FORM_MAX_BODY_BYTES} bytes`,
    })
  }
  const body = new TextDecoder().decode(bodyBytes)
  const formData = new URLSearchParams(body)
  const params = new URLSearchParams()
  let parameterCount = 0
  for (const [key, value] of formData) {
    parameterCount += 1
    if (parameterCount > OAUTH_FORM_MAX_PARAMETERS) {
      throw new OAuthError("invalid_request", {
        description: "Too many request parameters",
        detail: `OAuth form exceeded ${OAUTH_FORM_MAX_PARAMETERS} parameters`,
      })
    }
    const limitFailure = validateOAuthParameter(key, value)
    if (limitFailure !== null) {
      throw new OAuthError("invalid_request", {
        description: "A request parameter is invalid or too long",
        detail:
          limitFailure === "invalid_name"
            ? "OAuth form contained an invalid parameter name"
            : limitFailure === "invalid_value"
              ? `OAuth parameter ${key} had invalid syntax`
              : `OAuth parameter ${key} exceeded ${oauthParameterMaximumBytes(key)} bytes`,
      })
    }
    if (params.has(key)) {
      throw new OAuthError("invalid_request", {
        description: "Request parameters must not be repeated",
        detail: `duplicate OAuth form parameter: ${key}`,
      })
    }
    params.append(key, value)
  }
  return params
}

oauth.post("/oauth/token", async (c) => {
  const ipHash = await clientIpHash(c)
  await enforceOAuthRateLimit(c, `oauth:token:ip:${ipHash ?? "unknown"}`, 120)
  const form = await readFormBody(c)
  const grantType = form.get("grant_type")
  const { client } = await authenticateClient(c, form)
  await enforceOAuthRateLimit(
    c,
    client.type === "confidential"
      ? `oauth:token:client:${client.clientId}`
      : `oauth:token:client-ip:${client.clientId}:${ipHash ?? "unknown"}`,
    client.type === "confidential" ? 500 : 240,
  )

  switch (grantType) {
    case "client_credentials":
      return handleClientCredentials(c, client, form)
    case "authorization_code":
      return handleAuthorizationCode(c, client, form)
    case "refresh_token":
      return handleRefreshToken(c, client, form)
    case DEVICE_CODE_GRANT:
      return handleDeviceCodeGrant(c, client, form)
    default:
      throw new OAuthError("unsupported_grant_type", {
        description: "Unsupported grant_type",
        detail: `unknown grant_type: ${grantType ?? "<missing>"}`,
      })
  }
})

oauth.on(["GET", "POST"], "/oauth/userinfo", async (c) => {
  const ipHash = await clientIpHash(c)
  await enforceOAuthRateLimit(c, `oauth:userinfo:ip:${ipHash ?? "unknown"}`, 300)
  return handleUserInfo(c)
})

oauth.post("/oauth/device_authorization", async (c) => {
  const ipHash = await clientIpHash(c)
  await enforceOAuthRateLimit(c, `oauth:device:ip:${ipHash ?? "unknown"}`, 20)
  const form = await readFormBody(c)
  const { client } = await authenticateClient(c, form)
  await enforceOAuthRateLimit(
    c,
    client.type === "confidential"
      ? `oauth:device:client:${client.clientId}`
      : `oauth:device:client-ip:${client.clientId}:${ipHash ?? "unknown"}`,
    client.type === "confidential" ? 250 : 50,
  )
  return handleDeviceAuthorization(c, client, form)
})

oauth.post("/oauth/revoke", async (c) => {
  const ipHash = await clientIpHash(c)
  await enforceOAuthRateLimit(c, `oauth:revoke:ip:${ipHash ?? "unknown"}`, 120)
  const form = await readFormBody(c)
  const { client } = await authenticateClient(c, form)
  await enforceOAuthRateLimit(
    c,
    client.type === "confidential"
      ? `oauth:revoke:client:${client.clientId}`
      : `oauth:revoke:client-ip:${client.clientId}:${ipHash ?? "unknown"}`,
    client.type === "confidential" ? 500 : 240,
  )
  return handleRevoke(c, client, form)
})

oauth.post("/oauth/introspect", async (c) => {
  const ipHash = await clientIpHash(c)
  await enforceOAuthRateLimit(c, `oauth:introspect:ip:${ipHash ?? "unknown"}`, 120)
  const form = await readFormBody(c)
  const { client } = await authenticateClient(c, form)
  if (client.type !== "confidential" || client.clientKind !== "service") {
    throw new OAuthError("invalid_client", {
      status: 403,
      description: "Introspection requires an authorized resource service",
      detail: `non-service client ${client.clientId} attempted introspection`,
    })
  }
  await enforceOAuthRateLimit(c, `oauth:introspect:client:${client.clientId}`, 600)
  return handleIntrospect(c, form, client)
})
