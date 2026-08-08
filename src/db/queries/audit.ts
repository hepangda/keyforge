import * as z from "zod"

export type AuditLogEntry = {
  readonly id: string
  readonly eventType: string
  readonly actorUserId: string | null
  readonly actorClientId: string | null
  readonly userId: string | null
  readonly clientId: string | null
  readonly resourceUri: string | null
  readonly requestId: string | null
  readonly scope: string | null
  readonly success: boolean | null
  readonly detail: string | null
  readonly createdAt: number
}

const rowSchema = z.object({
  id: z.string(),
  event_type: z.string(),
  actor_user_id: z.string().nullable(),
  actor_client_id: z.string().nullable(),
  user_id: z.string().nullable(),
  client_id: z.string().nullable(),
  resource_uri: z.string().nullable(),
  request_id: z.string().nullable(),
  scope: z.string().nullable(),
  success: z.number().nullable(),
  detail: z.string().nullable(),
  created_at: z.number(),
})

const COLUMNS =
  "id, event_type, actor_user_id, actor_client_id, user_id, client_id, resource_uri, request_id, scope, success, detail, created_at"

function mapRow(row: unknown): AuditLogEntry {
  const parsed = rowSchema.parse(row)
  return {
    id: parsed.id,
    eventType: parsed.event_type,
    actorUserId: parsed.actor_user_id,
    actorClientId: parsed.actor_client_id,
    userId: parsed.user_id,
    clientId: parsed.client_id,
    resourceUri: parsed.resource_uri,
    requestId: parsed.request_id,
    scope: parsed.scope,
    success: parsed.success === null ? null : parsed.success === 1,
    detail: parsed.detail,
    createdAt: parsed.created_at,
  }
}

export type AuditLogQuery = {
  readonly limit: number
  readonly offset: number
  readonly userId?: string
  readonly clientId?: string
  readonly actorUserId?: string
  readonly actorClientId?: string
  readonly resourceUri?: string
  readonly eventType?: string
}

export async function listAuditLogs(env: Env, query: AuditLogQuery): Promise<AuditLogEntry[]> {
  const clauses: string[] = []
  const binds: unknown[] = []
  if (query.userId !== undefined) {
    clauses.push("user_id = ?")
    binds.push(query.userId)
  }
  if (query.clientId !== undefined) {
    clauses.push("client_id = ?")
    binds.push(query.clientId)
  }
  if (query.actorUserId !== undefined) {
    clauses.push("actor_user_id = ?")
    binds.push(query.actorUserId)
  }
  if (query.actorClientId !== undefined) {
    clauses.push("actor_client_id = ?")
    binds.push(query.actorClientId)
  }
  if (query.resourceUri !== undefined) {
    clauses.push("resource_uri = ?")
    binds.push(query.resourceUri)
  }
  if (query.eventType !== undefined) {
    clauses.push("event_type = ?")
    binds.push(query.eventType)
  }
  const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : ""
  const result = await env.DB.prepare(
    `SELECT ${COLUMNS} FROM audit_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(...binds, query.limit, query.offset)
    .all()
  return result.results.map(mapRow)
}
