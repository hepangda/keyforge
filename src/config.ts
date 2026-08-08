/**
 * Static, non-secret configuration for the KeyForge authorization server.
 * Runtime values that depend on the environment (issuer, cookie domain,
 * secrets) live on `Env`; everything here is a compile-time constant.
 */

/** Token lifetimes, in seconds. */
export const TOKEN_TTL = {
  /** OIDC id_token. */
  idToken: 600, // 10m
  /** User-facing access token (authorization_code / refresh / device). */
  userAccessToken: 900, // 15m
  /** Machine-to-machine (client_credentials) access token. */
  serviceAccessToken: 600, // 10m — spec allows 5-15m
  /** authorization_code single-use lifetime. */
  authorizationCode: 60, // 1m
  /** Refresh token default lifetime. */
  refreshToken: 30 * 24 * 60 * 60, // 30d
  /** Refresh token lifetime when "remember me" was selected. */
  refreshTokenRememberMe: 90 * 24 * 60 * 60, // 90d
  /** Device authorization grant lifetime. */
  deviceCode: 600, // 10m
  /** Magic link lifetime. */
  magicLink: 15 * 60, // 15m
  /** Email verification link lifetime. */
  emailVerification: 24 * 60 * 60, // 24h
  /** Password reset link lifetime. */
  passwordReset: 60 * 60, // 1h
  /** WebAuthn registration/authentication challenge lifetime. */
  webauthnChallenge: 5 * 60, // 5m
} as const

/**
 * Hard refresh-token family safety bounds. These are deliberately static so a
 * deployment cannot silently weaken replay protection through runtime config.
 */
export const REFRESH_TOKEN_POLICY = {
  /** The first rotation is immediate; later rotations must be this far apart. */
  minimumRotationIntervalSeconds: 10,
  /** Maximum successful rotations in one family before reauthorization is required. */
  maximumGeneration: 10_000,
  /** Maximum live authorizations retained for one user/client pair. */
  maximumActiveFamiliesPerUserClient: 20,
} as const

/** Default device polling interval advertised to clients, in seconds. */
export const DEVICE_POLL_INTERVAL_SECONDS = 5

/** Session lifetime bounds (seconds). Change through reviewed code, not mutable runtime vars. */
export const SESSION_TTL = {
  default: 30 * 24 * 60 * 60, // 30d
  rememberMe: 90 * 24 * 60 * 60, // 90d
} as const

/**
 * scrypt parameters for password hashing. N=2^15 is a strong,
 * Workers-CPU-viable setting (~16MB, memory-hard). Tune via migration if the
 * runtime CPU budget changes; the hash string is self-describing so old
 * hashes keep verifying after a parameter change.
 */
export const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 } as const

/** Every scope this server understands. */
export const SUPPORTED_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "api.read",
  "api.write",
  "admin.read",
  "admin.write",
  "app.read",
] as const

/** Audience and scopes accepted by the built-in JSON administrator API. */
export const ADMIN_API = {
  audience: "https://admin.pangda.app",
  readScope: "admin.read",
  writeScope: "admin.write",
} as const

/** Scopes that identify a user context and are therefore forbidden for client_credentials. */
export const USER_ONLY_SCOPES = ["openid", "profile", "email", "offline_access"] as const

/** Claims this server can assert. */
export const SUPPORTED_CLAIMS = [
  "sub",
  "email",
  "email_verified",
  "name",
  "preferred_username",
  "picture",
] as const

/** OAuth grant types this server implements. */
export const GRANT_TYPES = [
  "authorization_code",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code",
  "client_credentials",
] as const

export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

export const RESPONSE_TYPES = ["code"] as const
export const CODE_CHALLENGE_METHODS = ["S256"] as const
export const SUBJECT_TYPES = ["public"] as const
export const ID_TOKEN_SIGNING_ALG = ["RS256"] as const
export const TOKEN_ENDPOINT_AUTH_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "none",
] as const

/** JWT `typ` header values (RFC 9068 for access tokens). */
export const JWT_TYP = {
  idToken: "JWT",
  accessToken: "at+jwt",
} as const

/** Server-side session cookie. `__Host-` prefix mandates Secure + Path=/ + no Domain. */
export const SESSION_COOKIE_NAME = "__Host-keyforge_session"

/** Legacy KV keys read only while migrating pre-D1 signing-key state. */
export const KV_KEYS = {
  /** Historical JSON keyring, deleted after it is committed to D1. */
  signingKeys: "signing:keys",
  /** Historical active kid, deleted after it is committed to D1. */
  activeKid: "signing:active",
} as const
