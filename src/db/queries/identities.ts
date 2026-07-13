import { z } from "zod"
import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"

export type Identity = {
  readonly userId: string
  readonly provider: string
  readonly providerUserId: string
}

export async function getIdentityByProvider(
  env: Env,
  provider: string,
  providerUserId: string,
): Promise<Identity | null> {
  const row = await env.DB.prepare(
    "SELECT user_id, provider, provider_user_id FROM identities WHERE provider = ? AND provider_user_id = ?",
  )
    .bind(provider, providerUserId)
    .first()
  if (row === null) {
    return null
  }
  const parsed = z
    .object({ user_id: z.string(), provider: z.string(), provider_user_id: z.string() })
    .safeParse(row)
  return parsed.success
    ? {
        userId: parsed.data.user_id,
        provider: parsed.data.provider,
        providerUserId: parsed.data.provider_user_id,
      }
    : null
}

export async function getIdentityByUserAndProvider(
  env: Env,
  userId: string,
  provider: string,
): Promise<Identity | null> {
  const row = await env.DB.prepare(
    "SELECT user_id, provider, provider_user_id FROM identities WHERE user_id = ? AND provider = ?",
  )
    .bind(userId, provider)
    .first()
  if (row === null) {
    return null
  }
  const parsed = z
    .object({ user_id: z.string(), provider: z.string(), provider_user_id: z.string() })
    .safeParse(row)
  return parsed.success
    ? {
        userId: parsed.data.user_id,
        provider: parsed.data.provider,
        providerUserId: parsed.data.provider_user_id,
      }
    : null
}

export type CreateIdentityInput = {
  readonly userId: string
  readonly provider: string
  readonly providerUserId: string
  readonly email: string | null
  readonly emailVerified: boolean
  readonly profileJson: string | null
}

export async function createIdentity(env: Env, input: CreateIdentityInput): Promise<void> {
  const now = nowSeconds()
  await env.DB.prepare(
    `INSERT INTO identities
       (id, user_id, provider, provider_user_id, email, email_verified, profile_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      generateId(ID_PREFIX.identity),
      input.userId,
      input.provider,
      input.providerUserId,
      input.email,
      input.emailVerified ? 1 : 0,
      input.profileJson,
      now,
      now,
    )
    .run()
}

export type IdentitySummary = {
  readonly provider: string
  readonly email: string | null
}

export async function listIdentitiesByUser(env: Env, userId: string): Promise<IdentitySummary[]> {
  const result = await env.DB.prepare(
    "SELECT provider, email FROM identities WHERE user_id = ? ORDER BY created_at ASC",
  )
    .bind(userId)
    .all()
  const parsed = z
    .array(z.object({ provider: z.string(), email: z.string().nullable() }))
    .safeParse(result.results)
  return parsed.success
    ? parsed.data.map((row) => ({ provider: row.provider, email: row.email }))
    : []
}

export async function deleteIdentityByProvider(
  env: Env,
  userId: string,
  provider: string,
): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM identities WHERE user_id = ? AND provider = ?")
    .bind(userId, provider)
    .run()
  return result.meta.changes === 1
}

export type ProtectedIdentityDeleteResult = "deleted" | "not_found" | "last_login_method"

/** Delete a configured social login only when another usable method remains. */
export async function deleteIdentityPreservingLoginMethod(
  env: Env,
  userId: string,
  provider: string,
  configuredProviders: readonly string[],
): Promise<ProtectedIdentityDeleteResult> {
  const currentIsConfigured = configuredProviders.includes(provider)
  const otherProviders = configuredProviders.filter((candidate) => candidate !== provider)
  const otherIdentityClause =
    otherProviders.length === 0
      ? "0"
      : `EXISTS (
          SELECT 1 FROM identities other_i
          WHERE other_i.user_id = ?
            AND other_i.provider IN (${otherProviders.map(() => "?").join(",")})
        )`
  const result = await env.DB.prepare(
    `DELETE FROM identities
     WHERE user_id = ? AND provider = ?
       AND (
         ? = 0
         OR EXISTS (SELECT 1 FROM password_credentials p WHERE p.user_id = ?)
         OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = ?)
         OR ${otherIdentityClause}
       )`,
  )
    .bind(
      userId,
      provider,
      currentIsConfigured ? 1 : 0,
      userId,
      userId,
      ...(otherProviders.length === 0 ? [] : [userId, ...otherProviders]),
    )
    .run()
  if (result.meta.changes === 1) return "deleted"
  const exists = await env.DB.prepare(
    "SELECT 1 AS present FROM identities WHERE user_id = ? AND provider = ?",
  )
    .bind(userId, provider)
    .first()
  return exists === null ? "not_found" : "last_login_method"
}

export async function countIdentitiesByUser(env: Env, userId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM identities WHERE user_id = ?")
    .bind(userId)
    .first()
  const parsed = z.object({ n: z.number() }).safeParse(row)
  return parsed.success ? parsed.data.n : 0
}
