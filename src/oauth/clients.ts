import type { Context } from "hono"
import { getClientById } from "../db/queries/clients"
import { isYoloEnabled } from "../operations/yolo"
import { verifyClientSecret } from "../security/client-secret"
import { OAuthError } from "../security/errors"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"
import { OAUTH_BASIC_CREDENTIALS_MAX_ENCODED_BYTES, validateOAuthParameter } from "./request-limits"

export const CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"] as const
export type ClientAuthMethod = (typeof CLIENT_AUTH_METHODS)[number]

export type AuthenticatedClient = {
  readonly client: OAuthClient
  readonly method: ClientAuthMethod
}

type PresentedCredentials = {
  readonly clientId: string
  readonly clientSecret: string | null
  readonly method: ClientAuthMethod
}

function decodeBasic(header: string): { clientId: string; clientSecret: string } | null {
  const encoded = header.slice(6).trim()
  if (
    encoded === "" ||
    encoded.length > OAUTH_BASIC_CREDENTIALS_MAX_ENCODED_BYTES ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  ) {
    return null
  }
  let decoded: string
  try {
    const binary = atob(encoded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i)
    }
    decoded = new TextDecoder().decode(bytes)
  } catch (error) {
    if (error instanceof Error) {
      return null
    }
    throw error
  }
  const separator = decoded.indexOf(":")
  if (separator === -1) {
    return null
  }
  const clientId = decoded.slice(0, separator)
  const clientSecret = decoded.slice(separator + 1)
  if (
    validateOAuthParameter("client_id", clientId) !== null ||
    validateOAuthParameter("client_secret", clientSecret) !== null
  ) {
    return null
  }
  return { clientId, clientSecret }
}

function extractCredentials(
  c: Context<AppBindings>,
  form: URLSearchParams,
): PresentedCredentials | null {
  const authHeader = c.req.header("authorization")
  if (authHeader !== undefined && /^Basic /i.test(authHeader)) {
    const basic = decodeBasic(authHeader)
    if (basic === null) {
      return null
    }
    return {
      clientId: basic.clientId,
      clientSecret: basic.clientSecret,
      method: "client_secret_basic",
    }
  }
  const formClientId = form.get("client_id")
  if (formClientId === null) {
    return null
  }
  const formSecret = form.get("client_secret")
  if (
    validateOAuthParameter("client_id", formClientId) !== null ||
    (formSecret !== null && validateOAuthParameter("client_secret", formSecret) !== null)
  ) {
    return null
  }
  return {
    clientId: formClientId,
    clientSecret: formSecret,
    method: formSecret === null ? "none" : "client_secret_post",
  }
}

/**
 * Authenticate the client on a token-family endpoint. Confidential clients must
 * present a valid secret (Basic or post); public clients authenticate as
 * `none`. Every failure is a generic invalid_client with an internal detail.
 */
export async function authenticateClient(
  c: Context<AppBindings>,
  form: URLSearchParams,
): Promise<AuthenticatedClient> {
  const authHeader = c.req.header("authorization")
  if (authHeader !== undefined && !/^Basic /i.test(authHeader)) {
    throw new OAuthError("invalid_client", {
      status: 401,
      description: "Client authentication failed",
      detail: "unsupported Authorization scheme on a client-authenticated endpoint",
    })
  }
  if (
    authHeader !== undefined &&
    /^Basic /i.test(authHeader) &&
    (form.has("client_id") || form.has("client_secret"))
  ) {
    throw new OAuthError("invalid_client", {
      status: 401,
      description: "Client authentication failed",
      detail: "multiple client authentication methods were presented",
    })
  }
  const credentials = extractCredentials(c, form)
  if (credentials === null) {
    throw new OAuthError("invalid_client", {
      status: 401,
      description: "Client authentication required",
      detail: "no client credentials in Authorization header or request body",
    })
  }
  const client = await getClientById(c.env, credentials.clientId)
  if (client === null || !client.enabled) {
    throw new OAuthError("invalid_client", {
      status: 401,
      description: "Client authentication failed",
      detail: `client ${credentials.clientId} not found or disabled`,
    })
  }
  // YOLO mode accepts whatever credential shape the caller presented, as long
  // as the client itself exists and is enabled.
  if (isYoloEnabled(c.env)) {
    return { client, method: credentials.method }
  }
  if (client.type === "confidential") {
    const verified =
      credentials.clientSecret !== null &&
      client.clientSecretHash !== null &&
      (await verifyClientSecret(credentials.clientSecret, client.clientSecretHash))
    if (!verified) {
      throw new OAuthError("invalid_client", {
        status: 401,
        description: "Client authentication failed",
        detail: `invalid secret for confidential client ${credentials.clientId}`,
      })
    }
  } else if (credentials.method !== "none" || credentials.clientSecret !== null) {
    throw new OAuthError("invalid_client", {
      status: 401,
      description: "Client authentication failed",
      detail: `public client ${credentials.clientId} must use token endpoint auth method none`,
    })
  }
  return { client, method: credentials.method }
}
