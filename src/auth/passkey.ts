import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server"
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"
import {
  getCredentialByCredentialId,
  getCredentialsByUser,
  insertCredential,
  updateCredentialCounter,
} from "../db/queries/webauthn"
import type { User } from "../types/domain"
import { base64UrlDecode, base64UrlEncode } from "../utils/base64url"

const VALID_TRANSPORTS = new Set<string>([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
])

function toTransports(values: readonly string[]): AuthenticatorTransportFuture[] {
  return values.filter((value): value is AuthenticatorTransportFuture =>
    VALID_TRANSPORTS.has(value),
  )
}

// Copy into a fresh ArrayBuffer-backed view: @simplewebauthn requires
// `Uint8Array<ArrayBuffer>`, but TextEncoder/atob yield `Uint8Array<ArrayBufferLike>`.
function strictBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.length)
  out.set(bytes)
  return out
}

export function rpConfig(env: Env): { rpID: string; rpName: string; origin: string } {
  const url = new URL(env.ISSUER)
  return { rpID: url.hostname, rpName: "KeyForge", origin: env.ISSUER }
}

export async function buildRegistrationOptions(
  env: Env,
  user: User,
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const { rpID, rpName } = rpConfig(env)
  const existing = await getCredentialsByUser(env, user.id)
  return generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.email,
    userID: strictBytes(new TextEncoder().encode(user.id)),
    userDisplayName: user.name ?? user.email,
    attestationType: "none",
    excludeCredentials: existing.map((credential) => ({
      id: credential.credentialId,
      transports: toTransports(credential.transports),
    })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  })
}

export async function verifyAndStoreRegistration(
  env: Env,
  user: User,
  response: unknown,
  expectedChallenge: string,
): Promise<boolean> {
  const { rpID, origin } = rpConfig(env)
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>
  try {
    verification = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    })
  } catch (error) {
    if (error instanceof Error) {
      return false
    }
    throw error
  }
  if (!verification.verified || verification.registrationInfo === undefined) {
    return false
  }
  const credential = verification.registrationInfo.credential
  await insertCredential(env, {
    userId: user.id,
    credentialId: credential.id,
    publicKey: base64UrlEncode(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports ?? [],
    name: null,
  })
  return true
}

export function buildAuthenticationOptions(
  env: Env,
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return generateAuthenticationOptions({ rpID: rpConfig(env).rpID, userVerification: "required" })
}

function extractCredentialId(response: unknown): string | null {
  if (
    typeof response === "object" &&
    response !== null &&
    "id" in response &&
    typeof response.id === "string"
  ) {
    return response.id
  }
  return null
}

export async function verifyAuthentication(
  env: Env,
  response: unknown,
  expectedChallenge: string,
): Promise<string | null> {
  const credentialId = extractCredentialId(response)
  if (credentialId === null) {
    return null
  }
  const stored = await getCredentialByCredentialId(env, credentialId)
  if (stored === null) {
    return null
  }
  const { rpID, origin } = rpConfig(env)
  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>
  try {
    verification = await verifyAuthenticationResponse({
      response: response as AuthenticationResponseJSON,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: stored.credentialId,
        publicKey: strictBytes(base64UrlDecode(stored.publicKey)),
        counter: stored.counter,
        transports: toTransports(stored.transports),
      },
      requireUserVerification: true,
    })
  } catch (error) {
    if (error instanceof Error) {
      return null
    }
    throw error
  }
  if (!verification.verified) {
    return null
  }
  if (
    !(await updateCredentialCounter(
      env,
      stored.credentialId,
      stored.counter,
      verification.authenticationInfo.newCounter,
    ))
  ) {
    // A concurrent assertion advanced this credential after verification.
    // Failing closed prevents an older assertion from decreasing the counter.
    return null
  }
  return stored.userId
}
