import { hashOpaqueToken } from "../tokens/token-hash"
import { randomToken } from "../utils/random"
import { nowSeconds } from "../utils/time"
import { sha256Hex } from "./crypto"
import { safeLocalPath } from "./return-to"

const REAUTH_PROOF_PARAM = "_keyforge_reauth"
const REAUTH_PROOF_TTL_SECONDS = 5 * 60

function canonicalReturnTo(raw: string): string {
  const safe = safeLocalPath(raw)
  const url = new URL(safe, "https://keyforge.invalid")
  url.searchParams.delete(REAUTH_PROOF_PARAM)
  return `${url.pathname}${url.search}`
}

/**
 * Append a short-lived, one-time proof that a particular new session just
 * completed authentication for this exact local continuation URL.
 */
export async function createReauthContinuation(
  env: Env,
  sessionId: string,
  rawReturnTo: string,
): Promise<string> {
  const returnTo = canonicalReturnTo(rawReturnTo)
  const url = new URL(returnTo, "https://keyforge.invalid")
  if (url.pathname !== "/oauth/authorize") {
    return returnTo
  }
  const token = randomToken(24)
  const now = nowSeconds()
  await env.DB.prepare(
    `INSERT INTO reauth_continuations
       (token_hash, session_id, request_hash, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(
      await hashOpaqueToken(token),
      sessionId,
      await sha256Hex(returnTo),
      now + REAUTH_PROOF_TTL_SECONDS,
      now,
    )
    .run()
  url.searchParams.set(REAUTH_PROOF_PARAM, token)
  return `${url.pathname}${url.search}`
}

/**
 * Consume a continuation proof and, only on success, remove the interaction
 * requirements that the just-completed login satisfied. Invalid proofs are
 * ignored and therefore cannot weaken prompt/max_age handling.
 */
export async function consumeReauthContinuation(
  env: Env,
  sessionId: string | undefined,
  requestUrl: URL,
): Promise<URL> {
  const sanitized = new URL(requestUrl)
  const token = sanitized.searchParams.get(REAUTH_PROOF_PARAM)
  sanitized.searchParams.delete(REAUTH_PROOF_PARAM)
  if (token === null || token === "" || sessionId === undefined) {
    return sanitized
  }
  const canonical = `${sanitized.pathname}${sanitized.search}`
  const row = await env.DB.prepare(
    `UPDATE reauth_continuations SET consumed_at = ?
     WHERE token_hash = ? AND session_id = ? AND request_hash = ?
       AND consumed_at IS NULL AND expires_at > ?
     RETURNING token_hash`,
  )
    .bind(
      nowSeconds(),
      await hashOpaqueToken(token),
      sessionId,
      await sha256Hex(canonical),
      nowSeconds(),
    )
    .first()
  if (row === null) {
    return sanitized
  }

  const prompts = (sanitized.searchParams.get("prompt") ?? "")
    .trim()
    .split(/\s+/)
    .filter((prompt) => prompt !== "" && prompt !== "login")
  if (prompts.length === 0) sanitized.searchParams.delete("prompt")
  else sanitized.searchParams.set("prompt", prompts.join(" "))
  sanitized.searchParams.delete("max_age")
  return sanitized
}
