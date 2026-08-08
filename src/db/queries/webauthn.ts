import * as z from "zod"
import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"

export type StoredCredential = {
  readonly id: string
  readonly userId: string
  readonly credentialId: string
  readonly publicKey: string
  readonly counter: number
  readonly transports: string[]
}

const rowSchema = z.object({
  id: z.string(),
  user_id: z.string(),
  credential_id: z.string(),
  public_key: z.string(),
  counter: z.number(),
  transports: z.string().nullable(),
})

const COLUMNS = "id, user_id, credential_id, public_key, counter, transports"

function mapRow(row: unknown): StoredCredential {
  const parsed = rowSchema.parse(row)
  const transports = z.array(z.string()).safeParse(JSON.parse(parsed.transports ?? "[]"))
  return {
    id: parsed.id,
    userId: parsed.user_id,
    credentialId: parsed.credential_id,
    publicKey: parsed.public_key,
    counter: parsed.counter,
    transports: transports.success ? transports.data : [],
  }
}

export async function getCredentialsByUser(env: Env, userId: string): Promise<StoredCredential[]> {
  const result = await env.DB.prepare(
    `SELECT ${COLUMNS} FROM webauthn_credentials WHERE user_id = ?`,
  )
    .bind(userId)
    .all()
  return result.results.map(mapRow)
}

export async function getCredentialByCredentialId(
  env: Env,
  credentialId: string,
): Promise<StoredCredential | null> {
  const row = await env.DB.prepare(
    `SELECT ${COLUMNS} FROM webauthn_credentials WHERE credential_id = ?`,
  )
    .bind(credentialId)
    .first()
  return row === null ? null : mapRow(row)
}

export type InsertCredentialInput = {
  readonly userId: string
  readonly credentialId: string
  readonly publicKey: string
  readonly counter: number
  readonly transports: readonly string[]
  readonly name: string | null
}

export async function insertCredential(env: Env, input: InsertCredentialInput): Promise<void> {
  const now = nowSeconds()
  await env.DB.prepare(
    `INSERT INTO webauthn_credentials
       (id, user_id, credential_id, public_key, counter, transports, name, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      generateId(ID_PREFIX.webauthn),
      input.userId,
      input.credentialId,
      input.publicKey,
      input.counter,
      JSON.stringify(input.transports),
      input.name,
      now,
    )
    .run()
}

export async function updateCredentialCounter(
  env: Env,
  credentialId: string,
  expectedCounter: number,
  nextCounter: number,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE webauthn_credentials SET counter = ?, last_used_at = ?
     WHERE credential_id = ? AND counter = ?`,
  )
    .bind(nextCounter, nowSeconds(), credentialId, expectedCounter)
    .run()
  return result.meta.changes === 1
}

export type CredentialSummary = {
  readonly id: string
  readonly name: string | null
  readonly createdAt: number
  readonly lastUsedAt: number | null
  readonly transports: readonly string[]
}

const summaryRowSchema = z.object({
  id: z.string(),
  name: z.string().nullable(),
  transports: z.string().nullable(),
  created_at: z.number(),
  last_used_at: z.number().nullable(),
})

export async function listCredentialSummaries(
  env: Env,
  userId: string,
): Promise<CredentialSummary[]> {
  const result = await env.DB.prepare(
    "SELECT id, name, transports, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
  )
    .bind(userId)
    .all()
  return result.results.map((row) => {
    const parsed = summaryRowSchema.parse(row)
    const transports = z.array(z.string()).safeParse(JSON.parse(parsed.transports ?? "[]"))
    return {
      id: parsed.id,
      name: parsed.name,
      createdAt: parsed.created_at,
      lastUsedAt: parsed.last_used_at,
      transports: transports.success ? transports.data : [],
    }
  })
}

export async function renameCredential(
  env: Env,
  credentialId: string,
  userId: string,
  name: string | null,
): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?",
  )
    .bind(name, credentialId, userId)
    .run()
  return result.meta.changes === 1
}

export async function deleteCredential(
  env: Env,
  credentialId: string,
  userId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    "DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?",
  )
    .bind(credentialId, userId)
    .run()
  return result.meta.changes === 1
}

export type ProtectedCredentialDeleteResult = "deleted" | "not_found" | "last_login_method"

/** Delete only when another currently usable login method remains. */
export async function deleteCredentialPreservingLoginMethod(
  env: Env,
  credentialId: string,
  userId: string,
): Promise<ProtectedCredentialDeleteResult> {
  const result = await env.DB.prepare(
    `DELETE FROM webauthn_credentials
     WHERE id = ? AND user_id = ?
       AND (
         EXISTS (SELECT 1 FROM password_credentials p WHERE p.user_id = ?)
         OR EXISTS (
           SELECT 1 FROM webauthn_credentials w
           WHERE w.user_id = ? AND w.id != ?
         )
       )`,
  )
    .bind(credentialId, userId, userId, userId, credentialId)
    .run()
  if (result.meta.changes === 1) return "deleted"
  const exists = await env.DB.prepare(
    "SELECT 1 AS present FROM webauthn_credentials WHERE id = ? AND user_id = ?",
  )
    .bind(credentialId, userId)
    .first()
  return exists === null ? "not_found" : "last_login_method"
}

export async function countCredentialsByUser(env: Env, userId: string): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?",
  )
    .bind(userId)
    .first()
  const parsed = z.object({ n: z.number() }).safeParse(row)
  return parsed.success ? parsed.data.n : 0
}
