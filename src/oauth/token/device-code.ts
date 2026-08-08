import type { Context } from "hono"
import { getSessionById } from "../../auth/session"
import { DEVICE_CODE_GRANT } from "../../config"
import {
  consumeApprovedDevice,
  getDeviceByDeviceCodeHash,
  markDeviceExpired,
  recordDevicePoll,
  recordDeviceSlowPoll,
} from "../../db/queries/devices"
import { recordAuthorizationGrant } from "../../db/queries/grants"
import { markRefreshTokenRevoked } from "../../db/queries/tokens"
import { getUserById } from "../../db/queries/users"
import type { AuditEventType } from "../../security/audit"
import { recordAudit } from "../../security/audit"
import { OAuthError } from "../../security/errors"
import { hashOpaqueToken } from "../../tokens/token-hash"
import type { AppBindings } from "../../types/app"
import type { OAuthClient } from "../../types/domain"
import { assertNever } from "../../utils/assert"
import { isExpired, nowSeconds } from "../../utils/time"
import { consentCoversScopes } from "../consent"
import { resolveResourceForScopes } from "../resources"
import { parseScopeString } from "../scopes"
import { evaluateUserTokenAccess } from "../user-token-policy"
import { issueUserTokens } from "./issue"

export async function handleDeviceCodeGrant(
  c: Context<AppBindings>,
  client: OAuthClient,
  form: URLSearchParams,
): Promise<Response> {
  const env = c.env
  const deviceCode = form.get("device_code")
  if (deviceCode === null) {
    throw new OAuthError("invalid_request", {
      description: "Missing device_code",
      detail: "device_code grant without device_code",
    })
  }
  if (!client.allowedGrantTypes.includes(DEVICE_CODE_GRANT)) {
    throw new OAuthError("unauthorized_client", {
      description: "Client may not use the device flow",
      detail: `device_code grant not allowed for ${client.clientId}`,
    })
  }

  const session = await getDeviceByDeviceCodeHash(env, await hashOpaqueToken(deviceCode))
  if (session === null || session.clientId !== client.clientId) {
    throw new OAuthError("invalid_grant", {
      description: "Invalid device code",
      detail: "device_code not found or issued to a different client",
    })
  }
  if (isExpired(session.expiresAt)) {
    await markDeviceExpired(env, session.id)
    await deviceAudit(c, "oauth.device.expired", client.clientId, "device code expired")
    throw new OAuthError("expired_token", {
      description: "The device code has expired",
      detail: "device_code past its expiry",
    })
  }
  if (
    session.lastPolledAt !== null &&
    nowSeconds() - session.lastPolledAt < session.pollIntervalSeconds
  ) {
    await recordDeviceSlowPoll(env, session.id)
    await deviceAudit(c, "oauth.device.slow_down", client.clientId, "polled faster than interval")
    throw new OAuthError("slow_down", {
      description: "Polling too frequently",
      detail: "client polled faster than the advertised interval",
    })
  }
  await recordDevicePoll(env, session.id)

  switch (session.status) {
    case "pending":
      throw new OAuthError("authorization_pending", {
        description: "Authorization pending",
        detail: "user has not yet approved the device",
      })
    case "denied":
      await deviceAudit(c, "oauth.device.denied", client.clientId, "user denied the device")
      throw new OAuthError("access_denied", {
        status: 400,
        description: "The user denied the request",
        detail: "device authorization denied by the user",
      })
    case "expired":
      throw new OAuthError("expired_token", {
        description: "The device code has expired",
        detail: "device session already marked expired",
      })
    case "consumed":
      throw new OAuthError("invalid_grant", {
        description: "The device code was already used",
        detail: "device session already consumed",
      })
    case "approved":
      return issueDeviceTokens(
        c,
        client,
        session.id,
        session.userId,
        session.scope,
        session.resourceUri,
        session.sessionId,
        session.authTime,
      )
    default:
      return assertNever(session.status)
  }
}

async function issueDeviceTokens(
  c: Context<AppBindings>,
  client: OAuthClient,
  sessionId: string,
  userId: string | null,
  scope: string,
  resourceUri: string | null,
  browserSessionId: string | null,
  authTime: number | null,
): Promise<Response> {
  const env = c.env
  if (userId === null || resourceUri === null || browserSessionId === null || authTime === null) {
    throw new OAuthError("invalid_grant", {
      description: "Invalid device session",
      detail: "approved device session missing user, resource, or authentication context",
    })
  }
  const scopes = parseScopeString(scope)
  const resourceCheck = resolveResourceForScopes(env, client, resourceUri, scopes).then(
    () => ({ ok: true as const }),
    (error: unknown) => ({ ok: false as const, error }),
  )
  const [user, sourceSession, consentCovered, access, resource] = await Promise.all([
    getUserById(env, userId),
    getSessionById(env, browserSessionId),
    consentCoversScopes(env, userId, client.clientId, resourceUri, scopes),
    evaluateUserTokenAccess(env, {
      userId,
      clientId: client.clientId,
      resourceUri,
      scopes,
    }),
    resourceCheck,
  ])
  if (!resource.ok) throw resource.error
  if (user === null || user.disabled) {
    throw new OAuthError("invalid_grant", {
      description: "The account is unavailable",
      detail: `user ${userId} missing or disabled`,
    })
  }
  if (sourceSession === null || sourceSession.userId !== user.id || !consentCovered) {
    throw new OAuthError("invalid_grant", {
      description: "The device authorization was revoked",
      detail: "approving session or consent is no longer active",
    })
  }
  if (!access.allowed) {
    throw new OAuthError("invalid_grant", {
      description: "This account is not permitted to access this application or resource.",
      detail: `user token policy denied ${access.reason}`,
    })
  }
  if (!(await consumeApprovedDevice(env, sessionId))) {
    throw new OAuthError("invalid_grant", {
      description: "The device code was already used",
      detail: "approved device session lost the consume race",
    })
  }

  const response = await issueUserTokens(env, {
    user,
    client,
    scope,
    resource: resourceUri,
    nonce: null,
    authTime,
    // Once issued, the target device is independent of the browser that
    // approved it. Password reset/admin/app revocation still revoke all user
    // or client families, including these NULL-session families.
    sessionId: null,
    accessValidated: true,
  })
  const [sessionAfterIssue, consentAfterIssue] = await Promise.all([
    getSessionById(env, browserSessionId),
    consentCoversScopes(env, user.id, client.clientId, resourceUri, scopes),
  ])
  if (sessionAfterIssue === null || sessionAfterIssue.userId !== user.id || !consentAfterIssue) {
    const familyId = response.refresh_token?.split(".")[0]
    if (familyId !== undefined && familyId !== "") {
      await Promise.all([
        env.REFRESH_TOKEN_FAMILY.getByName(familyId).revoke(),
        markRefreshTokenRevoked(env, familyId),
      ])
    }
    throw new OAuthError("invalid_grant", {
      description: "The device authorization was revoked",
      detail: "authorization changed while device tokens were being issued",
    })
  }
  await recordAuthorizationGrant(env, {
    userId: user.id,
    clientId: client.clientId,
    sessionId: null,
    scope,
    resource: resourceUri,
    grantType: DEVICE_CODE_GRANT,
  })
  await deviceAudit(c, "oauth.device.consumed", client.clientId, "device code consumed")
  await recordAudit(env, {
    type: "oauth.token.issued",
    userId: user.id,
    clientId: client.clientId,
    resourceUri,
    scope,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.json(response, 200, { "cache-control": "no-store", pragma: "no-cache" })
}

function deviceAudit(
  c: Context<AppBindings>,
  type: AuditEventType,
  clientId: string,
  detail: string,
): Promise<void> {
  return recordAudit(c.env, {
    type,
    clientId,
    requestId: c.get("requestId"),
    success: true,
    detail,
  })
}
