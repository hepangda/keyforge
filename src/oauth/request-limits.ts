export const OAUTH_FORM_MAX_PARAMETERS = 32
export const OAUTH_FORM_MAX_BODY_BYTES = 64 * 1024
export const OAUTH_PARAMETER_NAME_MAX_BYTES = 64
export const OAUTH_PARAMETER_DEFAULT_MAX_BYTES = 2048
export const OAUTH_CLIENT_ID_MAX_BYTES = 128
export const OAUTH_CLIENT_SECRET_MAX_BYTES = 512

const OAUTH_PARAMETER_MAX_BYTES: Readonly<Record<string, number>> = {
  client_id: OAUTH_CLIENT_ID_MAX_BYTES,
  client_secret: OAUTH_CLIENT_SECRET_MAX_BYTES,
  grant_type: 128,
  code: 512,
  redirect_uri: 2048,
  code_verifier: 128,
  refresh_token: 512,
  device_code: 512,
  scope: 4096,
  resource: 2048,
  token: 16 * 1024,
  token_type_hint: 64,
  response_type: 64,
  state: 2048,
  nonce: 512,
  code_challenge: 128,
  code_challenge_method: 64,
  prompt: 128,
  max_age: 20,
  id_token_hint: 16 * 1024,
  post_logout_redirect_uri: 2048,
  _keyforge_reauth: 32,
}

/** Largest Base64 payload that can contain a bounded `client_id:client_secret` pair. */
export const OAUTH_BASIC_CREDENTIALS_MAX_ENCODED_BYTES =
  4 * Math.ceil((OAUTH_CLIENT_ID_MAX_BYTES + 1 + OAUTH_CLIENT_SECRET_MAX_BYTES) / 3)

const OAUTH_PARAMETER_NAME = /^[A-Za-z0-9._-]+$/
export const OAUTH_CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/
const REAUTH_CONTINUATION_PATTERN = /^[A-Za-z0-9_-]{32}$/
const encoder = new TextEncoder()

export type OAuthParameterLimitFailure = "invalid_name" | "invalid_value" | "value_too_long"

/** Validate one form field without ever reflecting its potentially sensitive value. */
export function validateOAuthParameter(
  name: string,
  value: string,
): OAuthParameterLimitFailure | null {
  if (
    name === "" ||
    encoder.encode(name).byteLength > OAUTH_PARAMETER_NAME_MAX_BYTES ||
    !OAUTH_PARAMETER_NAME.test(name)
  ) {
    return "invalid_name"
  }
  if (name === "client_id" && !OAUTH_CLIENT_ID_PATTERN.test(value)) {
    return "invalid_value"
  }
  if (name === "_keyforge_reauth" && !REAUTH_CONTINUATION_PATTERN.test(value)) {
    return "invalid_value"
  }
  const maximum = OAUTH_PARAMETER_MAX_BYTES[name] ?? OAUTH_PARAMETER_DEFAULT_MAX_BYTES
  return encoder.encode(value).byteLength <= maximum ? null : "value_too_long"
}

export function oauthParameterMaximumBytes(name: string): number {
  return OAUTH_PARAMETER_MAX_BYTES[name] ?? OAUTH_PARAMETER_DEFAULT_MAX_BYTES
}

export type OAuthParameterSetFailure =
  | { readonly kind: "too_many_parameters" }
  | { readonly kind: OAuthParameterLimitFailure }

/** Apply the same count, name, and value bounds to query or form parameters. */
export function validateOAuthParameterSet(
  parameters: Iterable<readonly [string, string]>,
): OAuthParameterSetFailure | null {
  let count = 0
  for (const [name, value] of parameters) {
    count += 1
    if (count > OAUTH_FORM_MAX_PARAMETERS) return { kind: "too_many_parameters" }
    const failure = validateOAuthParameter(name, value)
    if (failure !== null) return { kind: failure }
  }
  return null
}
