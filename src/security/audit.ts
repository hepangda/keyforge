import { z } from "zod"
import { generateId, ID_PREFIX } from "../utils/id"
import { nowSeconds } from "../utils/time"
import {
  isBoundedAuditDetail,
  isBoundedAuditMetadata,
  sanitizeAuditDetail,
  sanitizeAuditMetadata,
} from "./audit-sanitize"

/** Every security-relevant event this server records (spec §15). */
export const AUDIT_EVENTS = [
  "user.created",
  "user.login.password.success",
  "user.login.password.failure",
  "user.login.magic_link.requested",
  "user.login.magic_link.consumed",
  "user.login.passkey.success",
  "user.login.passkey.failure",
  "user.password.reset.requested",
  "user.password.reset.completed",
  "user.password.changed",
  "user.email.verification.requested",
  "user.email.verified",
  "user.email.change.requested",
  "user.email.changed",
  "user.profile.updated",
  "user.passkey.updated",
  "user.deleted",
  "user.logout",
  "oauth.authorize.started",
  "oauth.authorize.completed",
  "oauth.authorize.denied",
  "oauth.token.issued",
  "oauth.refresh.used",
  "oauth.refresh.reused",
  "oauth.token.revoked",
  "oauth.device.started",
  "oauth.device.approved",
  "oauth.device.denied",
  "oauth.device.pending",
  "oauth.device.slow_down",
  "oauth.device.consumed",
  "oauth.device.expired",
  "oauth.client_credentials.issued",
  "oauth.client_credentials.denied",
  "admin.client.created",
  "admin.client.updated",
  "admin.client.secret_rotated",
  "admin.client.disabled",
  "admin.client.enabled",
  "admin.user.updated",
  "admin.user.created",
  "admin.user.magic_link.generated",
  "admin.group.created",
  "admin.group.updated",
  "admin.group.deleted",
  "admin.user.groups_updated",
  "admin.device.revoked",
  "admin.resource.created",
  "admin.resource.updated",
  "security.rate_limited",
  "security.invalid_client",
  "security.invalid_redirect_uri",
  "security.invalid_pkce",
] as const

export type AuditEventType = (typeof AUDIT_EVENTS)[number]

export type AuditEvent = {
  readonly type: AuditEventType
  /** Authenticated principal that caused the event; separate from its subject. */
  readonly actorUserId?: string | null
  readonly actorClientId?: string | null
  readonly userId?: string | null
  readonly clientId?: string | null
  readonly resourceUri?: string | null
  readonly requestId?: string | null
  readonly ipHash?: string | null
  readonly userAgentHash?: string | null
  readonly scope?: string | null
  readonly success?: boolean
  /** Internal-only detail; safe to store, never returned to clients. */
  readonly detail?: string | null
  readonly metadata?: Record<string, unknown>
}

const auditMessageSchema = z.object({
  id: z.string(),
  type: z.enum(AUDIT_EVENTS),
  actorUserId: z.string().nullish(),
  actorClientId: z.string().nullish(),
  userId: z.string().nullish(),
  clientId: z.string().nullish(),
  resourceUri: z.string().nullish(),
  requestId: z.string().nullish(),
  ipHash: z.string().nullish(),
  userAgentHash: z.string().nullish(),
  scope: z.string().nullish(),
  success: z.boolean().nullish(),
  detail: z.string().refine(isBoundedAuditDetail).nullish(),
  metadata: z.record(z.string(), z.unknown()).refine(isBoundedAuditMetadata).nullish(),
  createdAt: z.number(),
})

type AuditMessage = z.infer<typeof auditMessageSchema>

/**
 * Enqueue an audit event with a stable id. If Queue is unavailable, persist
 * synchronously to D1 so a successful security mutation never silently loses
 * its audit record.
 */
export async function recordAudit(env: Env, event: AuditEvent): Promise<void> {
  const message: AuditMessage = {
    ...event,
    actorUserId: event.actorUserId,
    actorClientId: event.actorClientId,
    detail: sanitizeAuditDetail(event.detail),
    metadata: sanitizeAuditMetadata(event.metadata),
    id: generateId(ID_PREFIX.audit),
    createdAt: nowSeconds(),
  }
  try {
    await env.AUDIT_QUEUE.send(message)
  } catch (error) {
    console.error("audit.enqueue_failed", event.type, error)
    await insertAuditBatch(env, [message])
  }
}

function normalizeAuditMessage(raw: unknown): unknown {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return raw
  const message = raw as Record<string, unknown>
  return {
    ...message,
    ...(typeof message["detail"] === "string"
      ? { detail: sanitizeAuditDetail(message["detail"]) }
      : {}),
    ...(message["metadata"] === undefined
      ? {}
      : { metadata: sanitizeAuditMetadata(message["metadata"]) }),
  }
}

/** Persist a batch of audit messages (queue consumer path). */
export async function insertAuditBatch(env: Env, rawMessages: readonly unknown[]): Promise<void> {
  const messages = rawMessages.map((raw) => auditMessageSchema.parse(normalizeAuditMessage(raw)))
  if (messages.length === 0) {
    return
  }
  const stmt = env.DB.prepare(
    `INSERT OR IGNORE INTO audit_logs
       (id, event_type, actor_user_id, actor_client_id, user_id, client_id,
        resource_uri, request_id, ip_hash, user_agent_hash, scope, success,
        detail, metadata_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
  await env.DB.batch(
    messages.map((message) =>
      stmt.bind(
        message.id,
        message.type,
        message.actorUserId ?? null,
        message.actorClientId ?? null,
        message.userId ?? null,
        message.clientId ?? null,
        message.resourceUri ?? null,
        message.requestId ?? null,
        message.ipHash ?? null,
        message.userAgentHash ?? null,
        message.scope ?? null,
        message.success === undefined || message.success === null ? null : Number(message.success),
        message.detail ?? null,
        message.metadata === undefined || message.metadata === null
          ? null
          : JSON.stringify(message.metadata),
        message.createdAt,
      ),
    ),
  )
}
