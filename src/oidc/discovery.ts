import {
  CODE_CHALLENGE_METHODS,
  GRANT_TYPES,
  ID_TOKEN_SIGNING_ALG,
  RESPONSE_TYPES,
  SUBJECT_TYPES,
  SUPPORTED_CLAIMS,
  SUPPORTED_SCOPES,
  TOKEN_ENDPOINT_AUTH_METHODS,
} from "../config"
import { AUTHORIZE_PROMPTS } from "../oauth/authorize"

/** OpenID Provider metadata (OIDC Discovery 1.0 + RFC 8414). */
export type DiscoveryMetadata = {
  readonly issuer: string
  readonly authorization_endpoint: string
  readonly token_endpoint: string
  readonly device_authorization_endpoint: string
  readonly userinfo_endpoint: string
  readonly jwks_uri: string
  readonly revocation_endpoint: string
  readonly introspection_endpoint: string
  readonly end_session_endpoint: string
  readonly response_types_supported: readonly string[]
  readonly grant_types_supported: readonly string[]
  readonly subject_types_supported: readonly string[]
  readonly id_token_signing_alg_values_supported: readonly string[]
  readonly scopes_supported: readonly string[]
  readonly claims_supported: readonly string[]
  readonly code_challenge_methods_supported: readonly string[]
  readonly token_endpoint_auth_methods_supported: readonly string[]
  readonly prompt_values_supported: readonly string[]
}

/** Build the discovery document for a given issuer origin (no trailing slash). */
export function buildDiscoveryMetadata(issuer: string): DiscoveryMetadata {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    device_authorization_endpoint: `${issuer}/oauth/device_authorization`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    introspection_endpoint: `${issuer}/oauth/introspect`,
    end_session_endpoint: `${issuer}/oauth/end_session`,
    response_types_supported: RESPONSE_TYPES,
    grant_types_supported: GRANT_TYPES,
    subject_types_supported: SUBJECT_TYPES,
    id_token_signing_alg_values_supported: ID_TOKEN_SIGNING_ALG,
    scopes_supported: SUPPORTED_SCOPES,
    claims_supported: SUPPORTED_CLAIMS,
    code_challenge_methods_supported: CODE_CHALLENGE_METHODS,
    token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS,
    prompt_values_supported: AUTHORIZE_PROMPTS,
  }
}
