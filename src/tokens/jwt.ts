import type { JWTPayload, JWTVerifyOptions } from "jose"
import { createLocalJWKSet, decodeJwt, jwtVerify, SignJWT } from "jose"
import { JWT_TYP } from "../config"
import { nowSeconds } from "../utils/time"
import { getActiveSigningKey, getPublicJwks } from "./key-rotation"

const ALG = "RS256"

export type SignJwtOptions = {
  /** JWT `typ` header — `JWT` for id_token, `at+jwt` for access tokens. */
  readonly typ: string
  /** Lifetime in seconds; sets `exp = iat + expiresInSeconds`. */
  readonly expiresInSeconds: number
}

/**
 * Sign a JWT with the active RS256 key. The caller supplies all claims
 * (`iss`, `sub`, `aud`, `scope`, ...); this function owns only the header,
 * `iat`, and `exp` so lifetimes stay consistent across token types.
 */
export async function signJwt(
  env: Env,
  claims: JWTPayload,
  options: SignJwtOptions,
): Promise<string> {
  const { kid, privateKey } = await getActiveSigningKey(env)
  const issuedAt = nowSeconds()
  return new SignJWT(claims)
    .setProtectedHeader({ alg: ALG, kid, typ: options.typ })
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + options.expiresInSeconds)
    .sign(privateKey)
}

export type VerifyJwtOptions = {
  readonly issuer?: string
  readonly audience?: string
}

/**
 * Verify a JWT against the published JWKS. Throws (jose `JWT* ` errors) on any
 * signature/claim failure — callers convert to a generic OAuth error.
 */
export async function verifyJwt(
  env: Env,
  token: string,
  options: VerifyJwtOptions = {},
): Promise<JWTPayload> {
  const { keys } = await getPublicJwks(env)
  const jwks = createLocalJWKSet({ keys: [...keys] })
  const verifyOptions: JWTVerifyOptions = {
    algorithms: [ALG],
    issuer: options.issuer ?? env.ISSUER,
  }
  if (options.audience !== undefined) {
    verifyOptions.audience = options.audience
  }
  const { payload } = await jwtVerify(token, jwks, verifyOptions)
  return payload
}

/**
 * Verify a historical RP-logout ID token hint while deliberately ignoring its
 * expiry. Signature, algorithm, issuer, and all caller-side typ/audience/sub
 * checks still apply. The signed iat is used only as the JOSE validation time.
 */
export async function verifyHistoricalJwt(env: Env, token: string): Promise<JWTPayload> {
  const unverified = decodeJwt(token)
  if (typeof unverified.iat !== "number" || !Number.isSafeInteger(unverified.iat)) {
    throw new Error("historical JWT has no valid iat")
  }
  const { keys } = await getPublicJwks(env)
  const jwks = createLocalJWKSet({ keys: [...keys] })
  const { payload } = await jwtVerify(token, jwks, {
    algorithms: [ALG],
    issuer: env.ISSUER,
    currentDate: new Date(unverified.iat * 1000),
  })
  return payload
}

export type AccessTokenActor = "user" | "service" | "any"

export type VerifyAccessTokenOptions = {
  /** Resource audiences the caller is authorized to accept. */
  readonly audience?: string | readonly string[]
  /** Constrain the token to a user or service subject when the endpoint requires it. */
  readonly actor?: AccessTokenActor
}

/**
 * Verify an RFC 9068-style access token, including its explicit type and use.
 * Unlike the generic JWT verifier this rejects ID tokens even when they have a
 * valid signature, issuer, and otherwise-compatible claims.
 */
export async function verifyAccessToken(
  env: Env,
  token: string,
  options: VerifyAccessTokenOptions = {},
): Promise<JWTPayload> {
  const { keys } = await getPublicJwks(env)
  const jwks = createLocalJWKSet({ keys: [...keys] })
  const verifyOptions: JWTVerifyOptions = {
    algorithms: [ALG],
    issuer: env.ISSUER,
    typ: JWT_TYP.accessToken,
  }
  if (options.audience !== undefined) {
    verifyOptions.audience = [
      ...(typeof options.audience === "string" ? [options.audience] : options.audience),
    ]
  }
  const { payload, protectedHeader } = await jwtVerify(token, jwks, verifyOptions)
  if (protectedHeader.typ !== JWT_TYP.accessToken) {
    throw new Error("JWT is not an access token")
  }
  if (payload["token_use"] !== "access_token") {
    throw new Error("JWT token_use is not access_token")
  }
  if (
    !(
      (typeof payload.aud === "string" && payload.aud.length > 0) ||
      (Array.isArray(payload.aud) &&
        payload.aud.length > 0 &&
        payload.aud.every((audience) => audience.length > 0))
    )
  ) {
    throw new Error("Access token has no valid audience")
  }
  if (
    typeof payload.sub !== "string" ||
    payload.sub.length === 0 ||
    typeof payload["client_id"] !== "string" ||
    typeof payload["scope"] !== "string"
  ) {
    throw new Error("Access token is missing required claims")
  }

  const actor = options.actor ?? "any"
  const isService = payload["actor_type"] === "service" && payload.sub.startsWith("client:")
  if (actor === "user" && (isService || payload.sub.startsWith("client:"))) {
    throw new Error("Access token is not a user token")
  }
  if (actor === "service" && !isService) {
    throw new Error("Access token is not a service token")
  }
  return payload
}
