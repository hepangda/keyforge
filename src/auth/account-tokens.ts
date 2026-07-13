import { TOKEN_TTL } from "../config"
import { getUserSecurityVersion } from "../db/queries/users"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AccountOneTimeTokenPayload } from "../types/tokens"
import { generateId, ID_PREFIX } from "../utils/id"
import { randomToken } from "../utils/random"
import { nowSeconds } from "../utils/time"

type CreatedAccountToken = { readonly token: string; readonly url: string }

export async function createEmailVerificationToken(
  env: Env,
  userId: string,
  email: string,
): Promise<CreatedAccountToken> {
  const token = randomToken(32)
  const tokenHash = await hashOpaqueToken(token)
  const now = nowSeconds()
  const expiresAt = now + TOKEN_TTL.emailVerification
  const securityVersion = await getUserSecurityVersion(env, userId)
  if (securityVersion === null) throw new Error("account unavailable")
  const payload: AccountOneTimeTokenPayload = {
    purpose: "email_verification",
    userId,
    email,
    redirectTo: null,
    securityVersion,
  }
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE email_verifications SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL",
    ).bind(now, userId),
    env.DB.prepare(
      `INSERT INTO email_verifications
         (id, user_id, email, token_hash, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(generateId(ID_PREFIX.emailVerification), userId, email, tokenHash, now, expiresAt),
  ])
  await env.ONE_TIME_TOKEN.getByName(tokenHash).store(payload, TOKEN_TTL.emailVerification)
  return { token, url: `${env.ISSUER}/account/email/verify?token=${token}` }
}

export async function createEmailChangeToken(
  env: Env,
  userId: string,
  newEmail: string,
): Promise<CreatedAccountToken> {
  const token = randomToken(32)
  const tokenHash = await hashOpaqueToken(token)
  const now = nowSeconds()
  const expiresAt = now + TOKEN_TTL.emailVerification
  const securityVersion = await getUserSecurityVersion(env, userId)
  if (securityVersion === null) throw new Error("account unavailable")
  const payload: AccountOneTimeTokenPayload = {
    purpose: "email_change",
    userId,
    email: newEmail,
    redirectTo: null,
    securityVersion,
  }
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE email_verifications SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL",
    ).bind(now, userId),
    env.DB.prepare(
      `INSERT INTO email_verifications
         (id, user_id, email, token_hash, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(generateId(ID_PREFIX.emailVerification), userId, newEmail, tokenHash, now, expiresAt),
  ])
  await env.ONE_TIME_TOKEN.getByName(tokenHash).store(payload, TOKEN_TTL.emailVerification)
  return { token, url: `${env.ISSUER}/account/email/change/verify?token=${token}` }
}

export async function consumeEmailVerificationToken(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  const tokenHash = await hashOpaqueToken(token)
  const consumed = await env.ONE_TIME_TOKEN.getByName(tokenHash).consume()
  if (!consumed.found || consumed.value.purpose !== "email_verification") {
    return null
  }
  const result = await env.DB.prepare(
    `UPDATE email_verifications SET consumed_at = ?
     WHERE token_hash = ? AND user_id = ? AND email = ?
       AND consumed_at IS NULL AND expires_at > ?
       AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_version = ?)`,
  )
    .bind(
      nowSeconds(),
      tokenHash,
      consumed.value.userId,
      consumed.value.email,
      nowSeconds(),
      consumed.value.userId,
      consumed.value.securityVersion,
    )
    .run()
  return result.meta.changes === 1 ? consumed.value : null
}

async function peekEmailToken(
  env: Env,
  token: string,
  purpose: "email_verification" | "email_change",
): Promise<AccountOneTimeTokenPayload | null> {
  const tokenHash = await hashOpaqueToken(token)
  const peeked = await env.ONE_TIME_TOKEN.getByName(tokenHash).peek()
  if (!peeked.found || peeked.value.purpose !== purpose) return null
  const row = await env.DB.prepare(
    `SELECT 1 AS present FROM email_verifications
     WHERE token_hash = ? AND user_id = ? AND email = ?
       AND consumed_at IS NULL AND expires_at > ?
       AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_version = ?)`,
  )
    .bind(
      tokenHash,
      peeked.value.userId,
      peeked.value.email,
      nowSeconds(),
      peeked.value.userId,
      peeked.value.securityVersion,
    )
    .first()
  return row === null ? null : peeked.value
}

export function peekEmailVerificationToken(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  return peekEmailToken(env, token, "email_verification")
}

export async function consumeEmailChangeToken(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  const tokenHash = await hashOpaqueToken(token)
  const consumed = await env.ONE_TIME_TOKEN.getByName(tokenHash).consume()
  if (!consumed.found || consumed.value.purpose !== "email_change") {
    return null
  }
  const result = await env.DB.prepare(
    `UPDATE email_verifications SET consumed_at = ?
     WHERE token_hash = ? AND user_id = ? AND email = ?
       AND consumed_at IS NULL AND expires_at > ?
       AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_version = ?)`,
  )
    .bind(
      nowSeconds(),
      tokenHash,
      consumed.value.userId,
      consumed.value.email,
      nowSeconds(),
      consumed.value.userId,
      consumed.value.securityVersion,
    )
    .run()
  return result.meta.changes === 1 ? consumed.value : null
}

export function peekEmailChangeToken(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  return peekEmailToken(env, token, "email_change")
}

export async function createPasswordResetToken(
  env: Env,
  userId: string,
  email: string,
  purpose: "password_reset" | "account_invitation" = "password_reset",
): Promise<CreatedAccountToken> {
  const token = randomToken(32)
  const tokenHash = await hashOpaqueToken(token)
  const now = nowSeconds()
  const expiresAt = now + TOKEN_TTL.passwordReset
  const securityVersion = await getUserSecurityVersion(env, userId)
  if (securityVersion === null) throw new Error("account unavailable")
  const payload: AccountOneTimeTokenPayload = {
    purpose,
    userId,
    email,
    redirectTo: null,
    securityVersion,
  }
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO password_reset_tokens
         (id, user_id, token_hash, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(generateId(ID_PREFIX.passwordReset), userId, tokenHash, now, expiresAt),
  ])
  await env.ONE_TIME_TOKEN.getByName(tokenHash).store(payload, TOKEN_TTL.passwordReset)
  return { token, url: `${env.ISSUER}/password/reset?token=${token}` }
}

export function createAccountInvitationToken(
  env: Env,
  userId: string,
  email: string,
): Promise<CreatedAccountToken> {
  return createPasswordResetToken(env, userId, email, "account_invitation")
}

export async function peekPasswordResetToken(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  const tokenHash = await hashOpaqueToken(token)
  const result = await env.ONE_TIME_TOKEN.getByName(tokenHash).peek()
  if (
    !result.found ||
    (result.value.purpose !== "password_reset" && result.value.purpose !== "account_invitation")
  ) {
    return null
  }
  const row = await env.DB.prepare(
    `SELECT 1 AS present FROM password_reset_tokens
     WHERE token_hash = ? AND user_id = ? AND consumed_at IS NULL AND expires_at > ?`,
  )
    .bind(tokenHash, result.value.userId, nowSeconds())
    .first()
  if (row === null) return null
  return (await getUserSecurityVersion(env, result.value.userId)) === result.value.securityVersion
    ? result.value
    : null
}

export async function consumePasswordResetToken(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  const tokenHash = await hashOpaqueToken(token)
  const consumed = await env.ONE_TIME_TOKEN.getByName(tokenHash).consume()
  if (
    !consumed.found ||
    (consumed.value.purpose !== "password_reset" && consumed.value.purpose !== "account_invitation")
  ) {
    return null
  }
  const result = await env.DB.prepare(
    `UPDATE password_reset_tokens SET consumed_at = ?
     WHERE token_hash = ? AND user_id = ? AND consumed_at IS NULL AND expires_at > ?`,
  )
    .bind(nowSeconds(), tokenHash, consumed.value.userId, nowSeconds())
    .run()
  return result.meta.changes === 1 ? consumed.value : null
}
