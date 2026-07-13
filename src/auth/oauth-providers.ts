import { z } from "zod"
import { assertNever } from "../utils/assert"
import { fetchJson } from "../utils/fetch-json"
import type { SocialProfile, SocialProviderId } from "./account-linking"

type ProviderCredentials = { readonly clientId: string; readonly clientSecret: string }

type ProviderEndpoints = {
  readonly authorize: string
  readonly token: string
  readonly scope: string
}

function endpoints(provider: SocialProviderId): ProviderEndpoints {
  switch (provider) {
    case "github":
      return {
        authorize: "https://github.com/login/oauth/authorize",
        token: "https://github.com/login/oauth/access_token",
        scope: "read:user user:email",
      }
    case "google":
      return {
        authorize: "https://accounts.google.com/o/oauth2/v2/auth",
        token: "https://oauth2.googleapis.com/token",
        scope: "openid email profile",
      }
    default:
      return assertNever(provider)
  }
}

export function getProviderCredentials(
  env: Env,
  provider: SocialProviderId,
): ProviderCredentials | null {
  switch (provider) {
    case "github":
      return env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
        ? { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET }
        : null
    case "google":
      return env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
        ? { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET }
        : null
    default:
      return assertNever(provider)
  }
}

export type AuthorizeUrlParams = {
  readonly redirectUri: string
  readonly state: string
  readonly codeChallenge: string
}

export function buildAuthorizeUrl(
  env: Env,
  provider: SocialProviderId,
  params: AuthorizeUrlParams,
): string | null {
  const creds = getProviderCredentials(env, provider)
  if (creds === null) {
    return null
  }
  const { authorize, scope } = endpoints(provider)
  const url = new URL(authorize)
  url.searchParams.set("client_id", creds.clientId)
  url.searchParams.set("redirect_uri", params.redirectUri)
  url.searchParams.set("scope", scope)
  url.searchParams.set("state", params.state)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("code_challenge", params.codeChallenge)
  url.searchParams.set("code_challenge_method", "S256")
  if (provider === "google") {
    url.searchParams.set("access_type", "offline")
  }
  return url.toString()
}

export type ExchangeParams = {
  readonly code: string
  readonly redirectUri: string
  readonly codeVerifier: string
}

export async function exchangeCode(
  env: Env,
  provider: SocialProviderId,
  params: ExchangeParams,
): Promise<string | null> {
  const creds = getProviderCredentials(env, provider)
  if (creds === null) {
    return null
  }
  const body = new URLSearchParams({
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.codeVerifier,
    grant_type: "authorization_code",
  })
  const data = await fetchJson(endpoints(provider).token, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: body.toString(),
  })
  const parsed = z.object({ access_token: z.string() }).safeParse(data)
  return parsed.success ? parsed.data.access_token : null
}

export function fetchSocialProfile(
  provider: SocialProviderId,
  accessToken: string,
): Promise<SocialProfile> {
  switch (provider) {
    case "github":
      return fetchGithubProfile(accessToken)
    case "google":
      return fetchGoogleProfile(accessToken)
    default:
      return assertNever(provider)
  }
}

const githubUserSchema = z.object({
  id: z.number(),
  name: z.string().nullish(),
  avatar_url: z.string().nullish(),
  email: z.string().nullish(),
})
const githubEmailsSchema = z.array(
  z.object({ email: z.string(), primary: z.boolean(), verified: z.boolean() }),
)

async function fetchGithubProfile(accessToken: string): Promise<SocialProfile> {
  const headers = {
    authorization: `Bearer ${accessToken}`,
    accept: "application/vnd.github+json",
    "user-agent": "keyforge",
  }
  const user = githubUserSchema.parse(await fetchJson("https://api.github.com/user", { headers }))
  const emails = githubEmailsSchema.safeParse(
    await fetchJson("https://api.github.com/user/emails", { headers }),
  )
  const primary = emails.success
    ? emails.data.find((entry) => entry.primary && entry.verified)
    : undefined
  return {
    provider: "github",
    providerUserId: String(user.id),
    email: primary?.email ?? user.email ?? null,
    emailVerified: primary !== undefined,
    name: user.name ?? null,
    picture: user.avatar_url ?? null,
  }
}

const googleUserSchema = z.object({
  sub: z.string(),
  email: z.string().nullish(),
  email_verified: z.union([z.boolean(), z.string()]).nullish(),
  name: z.string().nullish(),
  picture: z.string().nullish(),
})

async function fetchGoogleProfile(accessToken: string): Promise<SocialProfile> {
  const user = googleUserSchema.parse(
    await fetchJson("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { authorization: `Bearer ${accessToken}` },
    }),
  )
  return {
    provider: "google",
    providerUserId: user.sub,
    email: user.email ?? null,
    emailVerified: user.email_verified === true || user.email_verified === "true",
    name: user.name ?? null,
    picture: user.picture ?? null,
  }
}
