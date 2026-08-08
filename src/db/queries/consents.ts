import * as z from "zod"
import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"

export type ConsentRecord = {
  readonly scope: string
  readonly resource: string | null
}

export async function getConsent(
  env: Env,
  userId: string,
  clientId: string,
  resource?: string | null,
): Promise<ConsentRecord | null> {
  const statement =
    resource === undefined
      ? env.DB.prepare(
          "SELECT scope, resource FROM consents WHERE user_id = ? AND client_id = ? ORDER BY updated_at DESC LIMIT 1",
        ).bind(userId, clientId)
      : env.DB.prepare(
          "SELECT scope, resource FROM consents WHERE user_id = ? AND client_id = ? AND resource = ?",
        ).bind(userId, clientId, resource ?? "")
  const row = await statement.first()
  if (row === null) {
    return null
  }
  const parsed = z.object({ scope: z.string(), resource: z.string().nullable() }).safeParse(row)
  if (!parsed.success) {
    return null
  }
  return { scope: parsed.data.scope, resource: parsed.data.resource || null }
}

export type SaveConsentInput = {
  readonly userId: string
  readonly clientId: string
  readonly scope: string
  readonly resource: string | null
}

export async function saveConsent(env: Env, input: SaveConsentInput): Promise<void> {
  const now = nowSeconds()
  await env.DB.prepare(
    `INSERT INTO consents (id, user_id, client_id, scope, resource, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, client_id, resource)
       DO UPDATE SET
         scope = (
           SELECT group_concat(value, ' ')
           FROM (
             SELECT value, MIN(source) AS source, MIN(position) AS position
             FROM (
               SELECT value, 0 AS source, key AS position
               FROM json_each('["' || replace(consents.scope, ' ', '","') || '"]')
               UNION ALL
               SELECT value, 1 AS source, key AS position
               FROM json_each('["' || replace(excluded.scope, ' ', '","') || '"]')
             )
             GROUP BY value
             ORDER BY source, position
           )
         ),
         updated_at = excluded.updated_at`,
  )
    .bind(
      generateId(ID_PREFIX.consent),
      input.userId,
      input.clientId,
      input.scope,
      input.resource ?? "",
      now,
      now,
    )
    .run()
}

export type ConsentSummary = {
  readonly clientId: string
  readonly clientName: string
  readonly scope: string
  readonly resource: string | null
}

export async function listConsentsByUser(env: Env, userId: string): Promise<ConsentSummary[]> {
  const result = await env.DB.prepare(
    `SELECT consent.client_id, client.name AS client_name, consent.scope, consent.resource
     FROM consents consent
     JOIN oauth_clients client ON client.client_id = consent.client_id
     WHERE consent.user_id = ?
     ORDER BY consent.updated_at DESC`,
  )
    .bind(userId)
    .all()
  const parsed = z
    .array(
      z.object({
        client_id: z.string(),
        client_name: z.string(),
        scope: z.string(),
        resource: z.string().nullable(),
      }),
    )
    .safeParse(result.results)
  return parsed.success
    ? parsed.data.map((row) => ({
        clientId: row.client_id,
        clientName: row.client_name,
        scope: row.scope,
        resource: row.resource || null,
      }))
    : []
}

export async function deleteConsent(env: Env, userId: string, clientId: string): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM consents WHERE user_id = ? AND client_id = ?")
    .bind(userId, clientId)
    .run()
  return result.meta.changes >= 1
}
