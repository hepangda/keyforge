import { TOKEN_TTL } from "../config"
import { getUserSecurityVersion } from "../db/queries/users"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { AccountOneTimeTokenPayload } from "../types/tokens"
import { randomToken } from "../utils/random"

export type MagicLinkInput = {
  readonly userId: string
  readonly email: string
  readonly redirectTo: string | null
  readonly reauthenticate?: boolean
}

export async function createMagicLink(
  env: Env,
  input: MagicLinkInput,
): Promise<{ token: string; url: string }> {
  const token = randomToken(32)
  const securityVersion = await getUserSecurityVersion(env, input.userId)
  if (securityVersion === null) throw new Error("account unavailable")
  const payload: AccountOneTimeTokenPayload = {
    purpose: "magic_link",
    userId: input.userId,
    email: input.email,
    redirectTo: input.redirectTo,
    reauthenticate: input.reauthenticate === true,
    securityVersion,
  }
  await env.ONE_TIME_TOKEN.getByName(await hashOpaqueToken(token)).store(
    payload,
    TOKEN_TTL.magicLink,
  )
  return { token, url: `${env.ISSUER}/login/magic/callback?token=${token}` }
}

export async function consumeMagicLink(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  const result = await env.ONE_TIME_TOKEN.getByName(await hashOpaqueToken(token)).consume()
  if (!result.found || result.value.purpose !== "magic_link") {
    return null
  }
  return (await getUserSecurityVersion(env, result.value.userId)) === result.value.securityVersion
    ? result.value
    : null
}

/** Inspect without consuming so mail scanners cannot burn a sign-in link. */
export async function peekMagicLink(
  env: Env,
  token: string,
): Promise<AccountOneTimeTokenPayload | null> {
  const result = await env.ONE_TIME_TOKEN.getByName(await hashOpaqueToken(token)).peek()
  if (!result.found || result.value.purpose !== "magic_link") return null
  return (await getUserSecurityVersion(env, result.value.userId)) === result.value.securityVersion
    ? result.value
    : null
}
