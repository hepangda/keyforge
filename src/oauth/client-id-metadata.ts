import * as z from "zod"
import {
  getClientById,
  isMetadataClientApproved,
  upsertMetadataClient,
} from "../db/queries/clients"
import { getResourceByUri } from "../db/queries/resources"
import { sha256Hex } from "../security/crypto"
import type { OAuthClient, TokenEndpointAuthMethod } from "../types/domain"
import { nowSeconds } from "../utils/time"
import { parseClientIdentifierUrl } from "./client-identifier"
import { RESOURCE_AUTHORIZED_SCOPES } from "./scope-policy"

const CLIENT_METADATA_MAX_BYTES = 5 * 1024
const DNS_RESPONSE_MAX_BYTES = 16 * 1024
const CLIENT_METADATA_FETCH_TIMEOUT_MS = 5_000
const CLIENT_METADATA_DEFAULT_TTL_SECONDS = 60 * 60
const CLIENT_METADATA_MAX_TTL_SECONDS = 24 * 60 * 60
const CLIENT_METADATA_MAX_REDIRECT_URIS = 16
const CLIENT_METADATA_MAX_REDIRECTS = 3

const metadataSchema = z.object({
  client_id: z.string().max(2048),
  client_name: z.string().trim().min(1).max(120),
  redirect_uris: z.array(z.string().max(2048)).min(1).max(CLIENT_METADATA_MAX_REDIRECT_URIS),
  grant_types: z.array(z.string().max(128)).min(1).max(2).default(["authorization_code"]),
  response_types: z.array(z.string().max(64)).min(1).max(1).default(["code"]),
  token_endpoint_auth_methods_supported: z
    .array(z.enum(["none", "private_key_jwt"]))
    .min(1)
    .max(2)
    .optional(),
  token_endpoint_auth_method: z.enum(["none", "private_key_jwt"]).optional(),
  jwks_uri: z.string().max(2048).optional(),
})

export type ClientIdMetadata = {
  readonly clientId: string
  readonly clientName: string
  readonly redirectUris: readonly string[]
  readonly allowedGrantTypes: readonly string[]
  readonly tokenEndpointAuthMethods: readonly TokenEndpointAuthMethod[]
  readonly jwksUri: string | null
  readonly fingerprint: string
  readonly expiresAt: number
}

export class ClientIdMetadataError extends Error {
  constructor(message: string, options: { readonly cause?: unknown } = {}) {
    super(message, options.cause === undefined ? {} : { cause: options.cause })
    this.name = "ClientIdMetadataError"
  }
}

export type ClientMetadataDependencies = {
  readonly fetcher?: typeof fetch
  readonly resolveHost?: (hostname: string) => Promise<readonly string[]>
}

function isSafeRedirectUri(raw: string): boolean {
  let url: URL
  if (raw.includes("#") || /(?:\*|%2a)/i.test(raw)) return false
  try {
    url = new URL(raw)
  } catch {
    return false
  }
  if (url.hash !== "" || url.username !== "" || url.password !== "") return false
  if (url.protocol === "https:") return url.hostname !== "" && !url.hostname.includes("*")
  if (url.protocol !== "http:") return false
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]"
}

function parseIpv4(raw: string): number | null {
  const parts = raw.split(".")
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value >>> 0
}

function ipv4InCidr(value: number, base: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return (value & mask) === (base & mask)
}

const SPECIAL_IPV4_RANGES = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const

function parseIpv6(raw: string): bigint | null {
  const input = raw.toLowerCase().split("%")[0]
  if (input === undefined || input === "") return null
  const halves = input.split("::")
  if (halves.length > 2) return null
  const parseHalf = (half: string): number[] | null => {
    if (half === "") return []
    const pieces = half.split(":")
    const result: number[] = []
    for (const piece of pieces) {
      const ipv4 = parseIpv4(piece)
      if (ipv4 !== null) {
        result.push((ipv4 >>> 16) & 0xffff, ipv4 & 0xffff)
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(piece)) return null
        result.push(Number.parseInt(piece, 16))
      }
    }
    return result
  }
  const left = parseHalf(halves[0] ?? "")
  const right = parseHalf(halves[1] ?? "")
  if (left === null || right === null) return null
  const missing = 8 - left.length - right.length
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null
  const words = [...left, ...new Array<number>(Math.max(0, missing)).fill(0), ...right]
  if (words.length !== 8) return null
  let value = 0n
  for (const word of words) value = (value << 16n) | BigInt(word)
  return value
}

function ipv6InCidr(value: bigint, base: bigint, prefix: number): boolean {
  const shift = BigInt(128 - prefix)
  return value >> shift === base >> shift
}

const SPECIAL_IPV6_RANGES = [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const

/** Reject every special-use address before making the metadata subrequest. */
export function isPublicInternetAddress(raw: string): boolean {
  const ipv4 = parseIpv4(raw)
  if (ipv4 !== null) {
    return !SPECIAL_IPV4_RANGES.some(([base, prefix]) => {
      const parsedBase = parseIpv4(base)
      return parsedBase !== null && ipv4InCidr(ipv4, parsedBase, prefix)
    })
  }
  const ipv6 = parseIpv6(raw.replace(/^\[|\]$/g, ""))
  if (ipv6 === null) return false
  return !SPECIAL_IPV6_RANGES.some(([base, prefix]) => {
    const parsedBase = parseIpv6(base)
    return parsedBase !== null && ipv6InCidr(ipv6, parsedBase, prefix)
  })
}

const dnsResponseSchema = z.object({
  Status: z.number(),
  Answer: z
    .array(z.object({ type: z.number(), data: z.string() }))
    .optional()
    .default([]),
})

async function resolvePublicHost(
  hostname: string,
  fetcher: typeof fetch,
): Promise<readonly string[]> {
  const literal = hostname.replace(/^\[|\]$/g, "")
  if (parseIpv4(literal) !== null || parseIpv6(literal) !== null) return [literal]
  const queries = [1, 28].map(async (type) => {
    const url = new URL("https://cloudflare-dns.com/dns-query")
    url.searchParams.set("name", hostname)
    url.searchParams.set("type", String(type))
    const response = await fetcher(url, {
      headers: { accept: "application/dns-json" },
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(CLIENT_METADATA_FETCH_TIMEOUT_MS),
    })
    if (!response.ok) {
      await response.body?.cancel()
      return []
    }
    const parsed = dnsResponseSchema.safeParse(
      await readBoundedJson(response, DNS_RESPONSE_MAX_BYTES),
    )
    return parsed.success && parsed.data.Status === 0
      ? parsed.data.Answer.filter((answer) => answer.type === type).map((answer) => answer.data)
      : []
  })
  const addresses = (await Promise.all(queries)).flat()
  if (addresses.length === 0)
    throw new ClientIdMetadataError("Client metadata host did not resolve")
  return addresses
}

async function readBoundedJson(
  response: Response,
  maximumBytes = CLIENT_METADATA_MAX_BYTES,
): Promise<unknown> {
  const declaredLength = response.headers.get("content-length")
  if (declaredLength !== null && Number(declaredLength) > maximumBytes) {
    await response.body?.cancel()
    throw new ClientIdMetadataError("Client metadata document is too large")
  }
  if (response.body === null) throw new ClientIdMetadataError("Client metadata document is empty")
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > maximumBytes) {
        await reader.cancel()
        throw new ClientIdMetadataError("Client metadata document is too large")
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch (error) {
    throw new ClientIdMetadataError("Client metadata document is not valid JSON", { cause: error })
  }
}

function metadataTtl(response: Response): number {
  const cacheControl = response.headers.get("cache-control")?.toLowerCase() ?? ""
  if (/(?:^|,)\s*(?:no-store|no-cache)(?:\s*=|\s*,|\s*$)/.test(cacheControl)) return 0
  const match = /(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*"?(\d+)"?/i.exec(cacheControl)
  if (match?.[1] === undefined) return CLIENT_METADATA_DEFAULT_TTL_SECONDS
  return Math.min(Number(match[1]), CLIENT_METADATA_MAX_TTL_SECONDS)
}

export type PublicJsonFetchResult = {
  readonly json: unknown
  readonly response: Response
  readonly finalUrl: URL
}

function isSafePublicFetchUrl(url: URL): boolean {
  return (
    url.protocol === "https:" &&
    url.hostname !== "" &&
    url.username === "" &&
    url.password === "" &&
    url.hash === ""
  )
}

/** Fetch bounded JSON while validating every DNS and redirect target. */
export async function fetchPublicJson(
  initialUrl: URL,
  dependencies: ClientMetadataDependencies = {},
  maximumBytes = CLIENT_METADATA_MAX_BYTES,
): Promise<PublicJsonFetchResult> {
  const fetcher = dependencies.fetcher ?? fetch
  const visited = new Set<string>()
  let url = initialUrl
  for (let redirects = 0; redirects <= CLIENT_METADATA_MAX_REDIRECTS; redirects += 1) {
    if (!isSafePublicFetchUrl(url) || visited.has(url.href)) {
      throw new ClientIdMetadataError("Client metadata target URL is unsafe")
    }
    visited.add(url.href)
    let addresses: readonly string[]
    try {
      addresses = await (dependencies.resolveHost === undefined
        ? resolvePublicHost(url.hostname, fetcher)
        : dependencies.resolveHost(url.hostname))
    } catch (error) {
      if (error instanceof ClientIdMetadataError) throw error
      throw new ClientIdMetadataError("Client metadata host could not be resolved", {
        cause: error,
      })
    }
    if (addresses.length === 0 || addresses.some((address) => !isPublicInternetAddress(address))) {
      throw new ClientIdMetadataError("Client metadata host resolved to a special-use address")
    }

    let response: Response
    try {
      response = await fetcher(url, {
        method: "GET",
        headers: { accept: "application/json, application/*+json" },
        cache: "no-store",
        redirect: "manual",
        signal: AbortSignal.timeout(CLIENT_METADATA_FETCH_TIMEOUT_MS),
      })
    } catch (error) {
      throw new ClientIdMetadataError("Client metadata document could not be fetched", {
        cause: error,
      })
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location")
      await response.body?.cancel()
      if (location === null || redirects === CLIENT_METADATA_MAX_REDIRECTS) {
        throw new ClientIdMetadataError("Client metadata redirect could not be followed safely")
      }
      try {
        url = new URL(location, url)
      } catch (error) {
        throw new ClientIdMetadataError("Client metadata redirect URL is invalid", { cause: error })
      }
      continue
    }
    if (response.status !== 200) {
      await response.body?.cancel()
      throw new ClientIdMetadataError("Client metadata endpoint did not return 200")
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim() ?? ""
    if (
      contentType !== "application/json" &&
      !/^application\/[a-z0-9!#$&^_.+-]+\+json$/i.test(contentType)
    ) {
      await response.body?.cancel()
      throw new ClientIdMetadataError("Client metadata endpoint did not return JSON")
    }
    return { json: await readBoundedJson(response, maximumBytes), response, finalUrl: url }
  }
  throw new ClientIdMetadataError("Client metadata redirect limit exceeded")
}

export async function fetchClientIdMetadata(
  clientId: string,
  dependencies: ClientMetadataDependencies = {},
): Promise<ClientIdMetadata> {
  const url = parseClientIdentifierUrl(clientId)
  if (url === null) throw new ClientIdMetadataError("Invalid Client Identifier URL")
  const { json: raw, response } = await fetchPublicJson(url, dependencies)
  if (
    typeof raw === "object" &&
    raw !== null &&
    ("client_secret" in raw || "client_secret_expires_at" in raw)
  ) {
    throw new ClientIdMetadataError("Client metadata must not contain shared secrets")
  }
  const parsed = metadataSchema.safeParse(raw)
  if (!parsed.success || parsed.data.client_id !== clientId) {
    throw new ClientIdMetadataError(
      "Client metadata document is malformed or has a mismatched client_id",
    )
  }
  if (
    new Set(parsed.data.redirect_uris).size !== parsed.data.redirect_uris.length ||
    parsed.data.redirect_uris.some((redirectUri) => !isSafeRedirectUri(redirectUri)) ||
    parsed.data.response_types.length !== 1 ||
    parsed.data.response_types[0] !== "code"
  ) {
    throw new ClientIdMetadataError("Client metadata requests unsupported or unsafe OAuth behavior")
  }
  if (
    new Set(parsed.data.grant_types).size !== parsed.data.grant_types.length ||
    !parsed.data.grant_types.includes("authorization_code") ||
    parsed.data.grant_types.some(
      (grant) => grant !== "authorization_code" && grant !== "refresh_token",
    )
  ) {
    throw new ClientIdMetadataError("Client metadata declares unsupported grant types")
  }
  const allowedGrantTypes = [...parsed.data.grant_types]
  const advertisedAuthMethods = parsed.data.token_endpoint_auth_methods_supported
  if (
    advertisedAuthMethods !== undefined &&
    new Set(advertisedAuthMethods).size !== advertisedAuthMethods.length
  ) {
    throw new ClientIdMetadataError("Client metadata authentication methods must be unique")
  }
  const tokenEndpointAuthMethods = [
    ...new Set(advertisedAuthMethods ?? [parsed.data.token_endpoint_auth_method ?? "none"]),
  ] satisfies TokenEndpointAuthMethod[]
  if (
    parsed.data.token_endpoint_auth_method !== undefined &&
    !tokenEndpointAuthMethods.includes(parsed.data.token_endpoint_auth_method)
  ) {
    throw new ClientIdMetadataError("Client metadata authentication preference is inconsistent")
  }
  let jwksUri: string | null = null
  if (parsed.data.jwks_uri !== undefined) {
    try {
      const jwksUrl = new URL(parsed.data.jwks_uri)
      if (
        !isSafePublicFetchUrl(jwksUrl) ||
        jwksUrl.origin !== url.origin ||
        jwksUrl.search !== "" ||
        jwksUrl.pathname === "/"
      ) {
        throw new Error("unsafe JWKS URI")
      }
      jwksUri = jwksUrl.href
    } catch (error) {
      throw new ClientIdMetadataError("Client metadata JWKS URI is invalid", { cause: error })
    }
  }
  if (tokenEndpointAuthMethods.includes("private_key_jwt") && jwksUri === null) {
    throw new ClientIdMetadataError("private_key_jwt metadata requires a same-origin JWKS URI")
  }
  const normalized = {
    client_id: clientId,
    client_name: parsed.data.client_name,
    redirect_uris: parsed.data.redirect_uris,
    grant_types: allowedGrantTypes,
    response_types: ["code"],
    token_endpoint_auth_methods_supported: tokenEndpointAuthMethods,
    jwks_uri: jwksUri,
  }
  return {
    clientId,
    clientName: normalized.client_name,
    redirectUris: normalized.redirect_uris,
    allowedGrantTypes,
    tokenEndpointAuthMethods,
    jwksUri,
    fingerprint: await sha256Hex(JSON.stringify(normalized)),
    expiresAt: nowSeconds() + metadataTtl(response),
  }
}

/** Resolve a static client or safely onboard/refresh an MCP metadata client. */
export async function resolveAuthorizationClient(
  env: Env,
  clientId: string,
  resourceUri: string | null,
  dependencies: ClientMetadataDependencies = {},
): Promise<OAuthClient | null> {
  const current = await getClientById(env, clientId)
  if (current !== null && current.registrationType === "static") return current
  if (parseClientIdentifierUrl(clientId) === null || resourceUri === null) return null
  const resource = await getResourceByUri(env, resourceUri)
  if (
    resource === null ||
    !resource.enabled ||
    !resource.mcpEnabled ||
    resource.metadataClientPolicy === "disabled"
  ) {
    return null
  }
  const allowedScopes = [...new Set([...resource.allowedScopes, ...RESOURCE_AUTHORIZED_SCOPES])]

  let resolved: OAuthClient
  try {
    if (
      current !== null &&
      current.metadataFingerprint !== null &&
      (current.metadataExpiresAt ?? 0) > nowSeconds()
    ) {
      resolved = await upsertMetadataClient(env, {
        clientId,
        name: current.name,
        redirectUris: current.redirectUris,
        allowedGrantTypes: current.allowedGrantTypes,
        tokenEndpointAuthMethods: current.tokenEndpointAuthMethods,
        metadataJwksUri: current.metadataJwksUri,
        metadataFingerprint: current.metadataFingerprint,
        resourceUri,
        allowedScopes,
        metadataExpiresAt: current.metadataExpiresAt ?? nowSeconds(),
      })
    } else {
      const metadata = await fetchClientIdMetadata(clientId, dependencies)
      resolved = await upsertMetadataClient(env, {
        clientId,
        name: metadata.clientName,
        redirectUris: metadata.redirectUris,
        allowedGrantTypes: metadata.allowedGrantTypes,
        tokenEndpointAuthMethods: metadata.tokenEndpointAuthMethods,
        metadataJwksUri: metadata.jwksUri,
        metadataFingerprint: metadata.fingerprint,
        resourceUri,
        allowedScopes,
        metadataExpiresAt: metadata.expiresAt,
      })
    }
  } catch (error) {
    if (error instanceof ClientIdMetadataError) throw error
    throw new ClientIdMetadataError("Client metadata could not be persisted", { cause: error })
  }
  if (
    resource.metadataClientPolicy === "admin_approved" &&
    !(await isMetadataClientApproved(env, clientId, resourceUri))
  ) {
    return null
  }
  return resolved
}
