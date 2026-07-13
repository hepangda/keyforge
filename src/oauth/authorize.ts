import { TOKEN_TTL } from "../config"
import { getClientById } from "../db/queries/clients"
import type { OAuthErrorCode } from "../security/errors"
import { OAuthError } from "../security/errors"
import { hashOpaqueToken } from "../tokens/token-hash"
import type { OAuthClient, User } from "../types/domain"
import type { AuthorizationCodePayload } from "../types/tokens"
import { randomToken } from "../utils/random"
import { isValidS256Challenge } from "./pkce"
import { isRegisteredRedirectUri } from "./redirect"
import { validateOAuthParameterSet } from "./request-limits"
import { resolveResourceForScopes } from "./resources"
import { parseScopeString, serializeScopes, validateRequestedScopes } from "./scopes"

export type AuthorizeParams = {
  readonly clientId: string
  readonly client: OAuthClient
  readonly redirectUri: string
  readonly scopes: string[]
  readonly resource: string
  readonly state: string | null
  readonly nonce: string | null
  readonly codeChallenge: string
  readonly prompts: readonly AuthorizePrompt[]
  readonly maxAge: number | null
}

export const AUTHORIZE_PROMPTS = ["none", "login", "consent"] as const
export type AuthorizePrompt = (typeof AUTHORIZE_PROMPTS)[number]

export type AuthorizeValidation =
  | {
      readonly kind: "invalid_request_page"
      readonly description: string
      readonly reason: "invalid_request" | "invalid_client" | "invalid_redirect_uri"
      readonly clientId: string | null
    }
  | {
      readonly kind: "error_redirect"
      readonly redirectUri: string
      readonly state: string | null
      readonly error: OAuthErrorCode
      readonly description: string
    }
  | { readonly kind: "ok"; readonly params: AuthorizeParams }

function errorRedirect(
  redirectUri: string,
  state: string | null,
  error: OAuthErrorCode,
  description: string,
): AuthorizeValidation {
  return { kind: "error_redirect", redirectUri, state, error, description }
}

function parsePrompts(raw: string | null): readonly AuthorizePrompt[] | null {
  if (raw === null) {
    return []
  }
  const values = [...new Set(raw.trim().split(/\s+/).filter(Boolean))]
  if (
    values.length === 0 ||
    values.some((value) => !(AUTHORIZE_PROMPTS as readonly string[]).includes(value)) ||
    (values.includes("none") && values.length !== 1)
  ) {
    return null
  }
  return values as AuthorizePrompt[]
}

function parseMaxAge(raw: string | null): number | null | undefined {
  if (raw === null) {
    return null
  }
  if (!/^(0|[1-9]\d*)$/.test(raw)) {
    return undefined
  }
  const value = Number(raw)
  return Number.isSafeInteger(value) ? value : undefined
}

export async function validateAuthorizeRequest(
  env: Env,
  query: URLSearchParams,
): Promise<AuthorizeValidation> {
  if (validateOAuthParameterSet(query) !== null) {
    return {
      kind: "invalid_request_page",
      description: "The authorization request contains invalid or oversized parameters.",
      reason: "invalid_request",
      clientId: null,
    }
  }
  if (query.getAll("client_id").length !== 1) {
    return {
      kind: "invalid_request_page",
      description: "client_id must appear exactly once.",
      reason: "invalid_request",
      clientId: null,
    }
  }
  const clientId = query.get("client_id")
  if (clientId === null) {
    return {
      kind: "invalid_request_page",
      description: "Missing client_id.",
      reason: "invalid_request",
      clientId: null,
    }
  }
  const client = await getClientById(env, clientId)
  if (client === null || !client.enabled) {
    return {
      kind: "invalid_request_page",
      description: "Unknown client.",
      reason: "invalid_client",
      clientId,
    }
  }
  if (query.getAll("redirect_uri").length !== 1) {
    return {
      kind: "invalid_request_page",
      description: "redirect_uri must appear exactly once.",
      reason: "invalid_redirect_uri",
      clientId,
    }
  }
  const redirectUri = query.get("redirect_uri")
  if (redirectUri === null || !isRegisteredRedirectUri(client, redirectUri)) {
    return {
      kind: "invalid_request_page",
      description: "Invalid redirect_uri.",
      reason: "invalid_redirect_uri",
      clientId,
    }
  }

  // redirect_uri is now proven registered: remaining errors return to the client.
  const duplicateParameter = [
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "resource",
    "prompt",
    "max_age",
  ].find((name) => query.getAll(name).length > 1)
  if (duplicateParameter !== undefined) {
    return errorRedirect(
      redirectUri,
      null,
      "invalid_request",
      `${duplicateParameter} must not appear more than once`,
    )
  }
  const state = query.get("state")
  if (!client.allowedGrantTypes.includes("authorization_code")) {
    return errorRedirect(redirectUri, state, "unauthorized_client", "Flow not permitted for client")
  }
  if (query.get("response_type") !== "code") {
    return errorRedirect(
      redirectUri,
      state,
      "unsupported_response_type",
      "response_type must be code",
    )
  }
  const codeChallenge = query.get("code_challenge")
  if (
    codeChallenge === null ||
    !isValidS256Challenge(codeChallenge) ||
    query.get("code_challenge_method") !== "S256"
  ) {
    return errorRedirect(redirectUri, state, "invalid_request", "PKCE with S256 is required")
  }
  const scopes = parseScopeString(query.get("scope"))
  if (scopes.length === 0) {
    return errorRedirect(redirectUri, state, "invalid_scope", "At least one scope is required")
  }
  const prompts = parsePrompts(query.get("prompt"))
  if (prompts === null) {
    return errorRedirect(
      redirectUri,
      state,
      "invalid_request",
      "prompt must contain only none, login, or consent; none cannot be combined",
    )
  }
  const maxAge = parseMaxAge(query.get("max_age"))
  if (maxAge === undefined) {
    return errorRedirect(
      redirectUri,
      state,
      "invalid_request",
      "max_age must be a non-negative integer",
    )
  }

  try {
    const validatedScopes = validateRequestedScopes(scopes, client.allowedScopes)
    const resource = await resolveResourceForScopes(
      env,
      client,
      query.get("resource"),
      validatedScopes,
    )
    return {
      kind: "ok",
      params: {
        clientId,
        client,
        redirectUri,
        scopes: validatedScopes,
        resource,
        state,
        nonce: query.get("nonce"),
        codeChallenge,
        prompts,
        maxAge,
      },
    }
  } catch (error) {
    if (error instanceof OAuthError) {
      return errorRedirect(redirectUri, state, error.code, error.message)
    }
    throw error
  }
}

export type AuthorizationSubject = {
  readonly user: User
  readonly sessionId: string
  readonly authTime: number
}

export async function issueAuthorizationCode(
  env: Env,
  params: AuthorizeParams,
  subject: AuthorizationSubject,
): Promise<string> {
  const code = randomToken(32)
  const payload: AuthorizationCodePayload = {
    clientId: params.clientId,
    userId: subject.user.id,
    redirectUri: params.redirectUri,
    scope: serializeScopes(params.scopes),
    resource: params.resource,
    codeChallenge: params.codeChallenge,
    codeChallengeMethod: "S256",
    nonce: params.nonce,
    authTime: subject.authTime,
    sessionId: subject.sessionId,
  }
  await env.AUTHORIZATION_CODE.getByName(await hashOpaqueToken(code)).store(
    payload,
    TOKEN_TTL.authorizationCode,
  )
  return code
}
