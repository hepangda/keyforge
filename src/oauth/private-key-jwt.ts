import { createLocalJWKSet, type JSONWebKeySet, type JWTPayload, jwtVerify } from "jose"
import * as z from "zod"
import { sha256Hex } from "../security/crypto"
import type { OAuthClient } from "../types/domain"
import { nowSeconds } from "../utils/time"
import {
  ClientIdMetadataError,
  type ClientMetadataDependencies,
  fetchPublicJson,
} from "./client-id-metadata"

const CLIENT_ASSERTION_MAX_LIFETIME_SECONDS = 5 * 60
const CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS = 5
const CLIENT_JWKS_MAX_BYTES = 16 * 1024
const CLIENT_JWKS_MAX_KEYS = 16
const CLIENT_ASSERTION_ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"] as const
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const

export const JWT_BEARER_CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const publicJwkSchema = z
  .object({
    kty: z.enum(["RSA", "EC", "OKP"]),
    kid: z.string().min(1).max(256),
    use: z.literal("sig").optional(),
    alg: z.enum(CLIENT_ASSERTION_ALGORITHMS).optional(),
    key_ops: z.array(z.string()).optional(),
  })
  .passthrough()
  .superRefine((key, context) => {
    if (PRIVATE_JWK_FIELDS.some((field) => field in key)) {
      context.addIssue({ code: "custom", message: "private key material is forbidden" })
    }
    if (key.key_ops !== undefined && !key.key_ops.includes("verify")) {
      context.addIssue({ code: "custom", message: "key cannot verify signatures" })
    }
  })

const jwksSchema = z
  .object({ keys: z.array(publicJwkSchema).min(1).max(CLIENT_JWKS_MAX_KEYS) })
  .strict()
  .refine((jwks) => new Set(jwks.keys.map((key) => key.kid)).size === jwks.keys.length)

export class PrivateKeyJwtError extends Error {
  constructor(message: string, options: { readonly cause?: unknown } = {}) {
    super(message, options.cause === undefined ? {} : { cause: options.cause })
    this.name = "PrivateKeyJwtError"
  }
}

export async function verifyPrivateKeyJwt(
  env: Env,
  client: OAuthClient,
  assertion: string,
  audience: string,
  dependencies: ClientMetadataDependencies = {},
): Promise<void> {
  if (
    client.registrationType !== "client_id_metadata" ||
    !client.tokenEndpointAuthMethods.includes("private_key_jwt") ||
    client.metadataJwksUri === null
  ) {
    throw new PrivateKeyJwtError("Client is not configured for private_key_jwt")
  }

  let document: unknown
  try {
    document = (
      await fetchPublicJson(new URL(client.metadataJwksUri), dependencies, CLIENT_JWKS_MAX_BYTES)
    ).json
  } catch (error) {
    if (error instanceof ClientIdMetadataError) {
      throw new PrivateKeyJwtError("Client JWKS could not be fetched safely", { cause: error })
    }
    throw error
  }
  const parsed = jwksSchema.safeParse(document)
  if (!parsed.success) throw new PrivateKeyJwtError("Client JWKS is malformed or unsafe")
  const jwks = document as JSONWebKeySet

  let payload: JWTPayload
  try {
    const verified = await jwtVerify(assertion, createLocalJWKSet(jwks), {
      algorithms: [...CLIENT_ASSERTION_ALGORITHMS],
      issuer: client.clientId,
      subject: client.clientId,
      audience,
      clockTolerance: CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS,
    })
    payload = verified.payload
  } catch (error) {
    throw new PrivateKeyJwtError("Client assertion signature or claims are invalid", {
      cause: error,
    })
  }

  const now = nowSeconds()
  if (
    typeof payload.iat !== "number" ||
    !Number.isInteger(payload.iat) ||
    payload.iat < now - CLIENT_ASSERTION_MAX_LIFETIME_SECONDS ||
    payload.iat > now + CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS ||
    typeof payload.exp !== "number" ||
    !Number.isInteger(payload.exp) ||
    payload.exp <= now - CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS ||
    payload.exp > now + CLIENT_ASSERTION_MAX_LIFETIME_SECONDS ||
    typeof payload.jti !== "string" ||
    payload.jti.length < 1 ||
    payload.jti.length > 256
  ) {
    throw new PrivateKeyJwtError("Client assertion lifetime or jti is invalid")
  }

  const jtiHash = await sha256Hex(`${client.clientId}\u0000${payload.jti}`)
  const inserted = await env.DB.prepare(
    `INSERT OR IGNORE INTO oauth_client_assertion_jtis
       (jti_hash, client_id, expires_at, created_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(jtiHash, client.clientId, payload.exp, now)
    .run()
  if (inserted.meta.changes !== 1) {
    throw new PrivateKeyJwtError("Client assertion was already used")
  }
}
