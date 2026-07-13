/**
 * Typed errors. External responses expose only the standard OAuth `error`
 * code and a generic `error_description`; the internal `detail` is carried for
 * the audit log and is never serialized to the client.
 */

export const OAUTH_ERROR_CODES = [
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "unsupported_response_type",
  "invalid_scope",
  "invalid_target",
  "access_denied",
  "server_error",
  "temporarily_unavailable",
  "authorization_pending",
  "slow_down",
  "expired_token",
  "login_required",
  "consent_required",
  "interaction_required",
] as const

export type OAuthErrorCode = (typeof OAUTH_ERROR_CODES)[number]

const DEFAULT_STATUS: Record<OAuthErrorCode, number> = {
  invalid_request: 400,
  invalid_client: 401,
  invalid_grant: 400,
  unauthorized_client: 400,
  unsupported_grant_type: 400,
  unsupported_response_type: 400,
  invalid_scope: 400,
  invalid_target: 400,
  access_denied: 403,
  server_error: 500,
  temporarily_unavailable: 503,
  authorization_pending: 400,
  slow_down: 400,
  expired_token: 400,
  login_required: 401,
  consent_required: 401,
  interaction_required: 401,
}

export type OAuthErrorOptions = {
  readonly description?: string
  readonly status?: number
  readonly detail?: string
  readonly cause?: unknown
}

export type OAuthErrorBody = {
  readonly error: OAuthErrorCode
  readonly error_description: string
}

/** An OAuth/OIDC protocol error suitable for the token/authorize/device endpoints. */
export class OAuthError extends Error {
  readonly code: OAuthErrorCode
  readonly status: number
  /** Internal-only reason for the audit log. Never sent to the client. */
  readonly detail: string | undefined

  constructor(code: OAuthErrorCode, options: OAuthErrorOptions = {}) {
    super(options.description ?? code, options.cause === undefined ? {} : { cause: options.cause })
    this.name = "OAuthError"
    this.code = code
    this.status = options.status ?? DEFAULT_STATUS[code]
    this.detail = options.detail
  }

  /** Body safe to return to the client. */
  toBody(): OAuthErrorBody {
    return { error: this.code, error_description: this.message }
  }
}

/** A generic, non-OAuth application error (auth flows, admin API, etc.). */
export class AppError extends Error {
  readonly status: number
  /** Client-safe, generic message. */
  readonly publicMessage: string
  /** Internal-only reason for the audit log. */
  readonly detail: string | undefined

  constructor(
    status: number,
    publicMessage: string,
    options: { readonly detail?: string; readonly cause?: unknown } = {},
  ) {
    super(publicMessage, options.cause === undefined ? {} : { cause: options.cause })
    this.name = "AppError"
    this.status = status
    this.publicMessage = publicMessage
    this.detail = options.detail
  }
}
