import type { Hono } from "hono"
import * as z from "zod"
import type { AdminDeviceSession } from "../db/queries/admin-devices"
import {
  getDeviceSessionById,
  listDeviceSessions,
  revokeDeviceSession,
} from "../db/queries/admin-devices"
import type { AuditLogEntry } from "../db/queries/audit"
import { listAuditLogs } from "../db/queries/audit"
import {
  createResource,
  deleteResource,
  getResourceByUri,
  listResources,
  updateResource,
} from "../db/queries/resources"
import { validateScopeCatalog } from "../oauth/scopes"
import { recordAudit } from "../security/audit"
import { isMcpResourceUriAllowed, isSafeResourceUri } from "../security/redirect-uri"
import type { AppBindings } from "../types/app"
import type { OAuthResource } from "../types/domain"
import { parsePagination, readJsonBody } from "../utils/http"

const createResourceSchema = z.object({
  resource_uri: z.string().refine(isSafeResourceUri),
  name: z.string().min(1),
  allowed_scopes: z.array(z.string()).default([]),
  mcp_enabled: z.boolean().default(false),
  metadata_client_policy: z
    .enum(["disabled", "consent_required", "admin_approved"])
    .default("disabled"),
})

const patchResourceSchema = z.object({
  name: z.string().optional(),
  allowed_scopes: z.array(z.string()).optional(),
  enabled: z.boolean().optional(),
  mcp_enabled: z.boolean().optional(),
  metadata_client_policy: z.enum(["disabled", "consent_required", "admin_approved"]).optional(),
})

type MutableResourcePatch = {
  name?: string
  allowedScopes?: string[]
  enabled?: boolean
  mcpEnabled?: boolean
  metadataClientPolicy?: "disabled" | "consent_required" | "admin_approved"
}

function serializeResource(resource: OAuthResource): Record<string, unknown> {
  return {
    resource_uri: resource.resourceUri,
    name: resource.name,
    allowed_scopes: resource.allowedScopes,
    enabled: resource.enabled,
    mcp_enabled: resource.mcpEnabled,
    metadata_client_policy: resource.metadataClientPolicy,
  }
}

function serializeAudit(entry: AuditLogEntry): Record<string, unknown> {
  return {
    id: entry.id,
    event_type: entry.eventType,
    actor_user_id: entry.actorUserId,
    actor_client_id: entry.actorClientId,
    user_id: entry.userId,
    client_id: entry.clientId,
    resource_uri: entry.resourceUri,
    request_id: entry.requestId,
    scope: entry.scope,
    success: entry.success,
    detail: entry.detail,
    created_at: entry.createdAt,
  }
}

function serializeDevice(session: AdminDeviceSession): Record<string, unknown> {
  return {
    id: session.id,
    client_id: session.clientId,
    resource_uri: session.resourceUri,
    scope: session.scope,
    status: session.status,
    user_id: session.userId,
    expires_at: session.expiresAt,
    approved_at: session.approvedAt,
    denied_at: session.deniedAt,
    last_polled_at: session.lastPolledAt,
    poll_count: session.pollCount,
    created_at: session.createdAt,
  }
}

export function registerAdminCatalog(app: Hono<AppBindings>): void {
  app.get("/admin/resources", async (c) =>
    c.json({ resources: (await listResources(c.env)).map(serializeResource) }),
  )

  app.post("/admin/resources", async (c) => {
    const parsed = createResourceSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    if (
      !validateScopeCatalog(parsed.data.allowed_scopes).ok ||
      (parsed.data.metadata_client_policy !== "disabled" && !parsed.data.mcp_enabled) ||
      (parsed.data.mcp_enabled &&
        !isMcpResourceUriAllowed(c.env.ENVIRONMENT, parsed.data.resource_uri))
    ) {
      return c.json({ error: "invalid_request" }, 400)
    }
    await createResource(c.env, {
      resourceUri: parsed.data.resource_uri,
      name: parsed.data.name,
      allowedScopes: parsed.data.allowed_scopes,
      mcpEnabled: parsed.data.mcp_enabled,
      metadataClientPolicy: parsed.data.metadata_client_policy,
    })
    await recordAudit(c.env, {
      type: "admin.resource.created",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri: parsed.data.resource_uri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.json({ resource_uri: parsed.data.resource_uri }, 201)
  })

  app.patch("/admin/resources/:id", async (c) => {
    const parsed = patchResourceSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const patch: MutableResourcePatch = {}
    if (parsed.data.name !== undefined) patch.name = parsed.data.name
    if (parsed.data.allowed_scopes !== undefined) patch.allowedScopes = parsed.data.allowed_scopes
    if (parsed.data.enabled !== undefined) patch.enabled = parsed.data.enabled
    if (parsed.data.mcp_enabled !== undefined) patch.mcpEnabled = parsed.data.mcp_enabled
    if (parsed.data.metadata_client_policy !== undefined) {
      patch.metadataClientPolicy = parsed.data.metadata_client_policy
    }
    const current = await getResourceByUri(c.env, c.req.param("id"))
    if (current === null) return c.json({ error: "not_found" }, 404)
    const nextScopes = patch.allowedScopes ?? current.allowedScopes
    const nextMcpEnabled = patch.mcpEnabled ?? current.mcpEnabled
    const nextMetadataPolicy = patch.metadataClientPolicy ?? current.metadataClientPolicy
    if (
      !validateScopeCatalog(nextScopes).ok ||
      (nextMetadataPolicy !== "disabled" && !nextMcpEnabled) ||
      (nextMcpEnabled && !isMcpResourceUriAllowed(c.env.ENVIRONMENT, current.resourceUri))
    ) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const updated = await updateResource(c.env, c.req.param("id"), patch)
    if (updated === null) {
      return c.json({ error: "not_found" }, 404)
    }
    await recordAudit(c.env, {
      type: "admin.resource.updated",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri: updated.resourceUri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.json(serializeResource(updated))
  })

  app.delete("/admin/resources/:id", async (c) => {
    const resourceUri = c.req.param("id")
    if (!(await deleteResource(c.env, resourceUri))) {
      return c.json({ error: "not_found" }, 404)
    }
    await recordAudit(c.env, {
      type: "admin.resource.deleted",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.json({ deleted: true })
  })

  app.get("/admin/audit-logs", async (c) => {
    const { limit, offset } = parsePagination(c)
    const query: {
      limit: number
      offset: number
      userId?: string
      clientId?: string
      actorUserId?: string
      actorClientId?: string
      eventType?: string
    } = { limit, offset }
    const userId = c.req.query("user_id")
    if (userId !== undefined) query.userId = userId
    const clientId = c.req.query("client_id")
    if (clientId !== undefined) query.clientId = clientId
    const actorUserId = c.req.query("actor_user_id")
    if (actorUserId !== undefined) query.actorUserId = actorUserId
    const actorClientId = c.req.query("actor_client_id")
    if (actorClientId !== undefined) query.actorClientId = actorClientId
    const eventType = c.req.query("event_type")
    if (eventType !== undefined) query.eventType = eventType
    return c.json({ logs: (await listAuditLogs(c.env, query)).map(serializeAudit) })
  })

  app.get("/admin/device-sessions", async (c) => {
    const { limit, offset } = parsePagination(c)
    return c.json({
      device_sessions: (await listDeviceSessions(c.env, limit, offset)).map(serializeDevice),
    })
  })

  app.get("/admin/device-sessions/:id", async (c) => {
    const session = await getDeviceSessionById(c.env, c.req.param("id"))
    if (session === null) {
      return c.json({ error: "not_found" }, 404)
    }
    return c.json(serializeDevice(session))
  })

  app.post("/admin/device-sessions/:id/revoke", async (c) => {
    const id = c.req.param("id")
    if (!(await revokeDeviceSession(c.env, id))) {
      return c.json({ error: "not_found" }, 404)
    }
    await recordAudit(c.env, {
      type: "admin.device.revoked",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      detail: `admin revoked device session ${id}`,
    })
    return c.json({ revoked: true })
  })
}
