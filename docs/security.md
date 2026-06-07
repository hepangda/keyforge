# Security

## STRIDE threat model (abridged)

| Threat | Mitigation |
| --- | --- |
| Spoofing (impersonation) | OAuth 2.1 PKCE mandatory for public clients; mTLS-bound or DPoP-bound tokens for sensitive APIs; `private_key_jwt` available for confidential clients. |
| Tampering with tokens | JWT ID tokens signed by JWKS; opaque ATs hashed in DB; refresh-token reuse triggers family-wide revocation in a SERIALIZABLE tx. |
| Repudiation | Append-only `audit_log`; DB-level `REVOKE UPDATE,DELETE ON audit_log` so the keyforge role can only `INSERT`/`SELECT`. |
| Information disclosure | argon2id passwords; envelope-encrypted secrets (JWKS private keys, TOTP, IdP secrets); slog `ReplaceAttr` redacts password/secret/token/code/assertion/cookie/etc. |
| Denial of service | Token-bucket rate limiter on /oauth/token, /oauth/login, /oauth/par, /oauth/introspect, /oauth/revoke; admin port isolated. |
| Elevation of privilege | RBAC middleware on every admin route; tenant-isolated AT lookup; `tenantguard_test.go` build-time check on every sqlc query. |

## Token lifetimes

| Token | Default | Configurable | Notes |
| --- | --- | --- | --- |
| Access token | 1h | yes | opaque; SHA-256 hash in DB; instantly revocable |
| Refresh token | 30d | yes | rotated on every grant; reuse → family revoke |
| ID token | 10m | yes | JWT; signed by active JWKS key |
| Authorization code | 60s | yes | single-use; hashed |
| Device code | 5m | yes | poll interval 5s; `slow_down` on misbehaviour |
| CIBA `auth_req_id` | 5m | yes | same polling backoff as device |
| PAR request_uri | 90s | yes | single-use |
| WebAuthn challenge | 5m | yes | single-use; deletes on consume |

## Redirect URI policy

OAuth 2.1 exact-match enforcement. The single exception is the RFC 8252
loopback rule: a registered `http://127.0.0.1/path` matches the same
scheme/host/path on any port (so native apps can pick an ephemeral
listener). Wildcards are never accepted.

## mTLS proxy hardening

When `tls_client_auth` or `self_signed_tls_client_auth` is enabled,
keyforge reads the leaf certificate either directly from `r.TLS`
(`mtls.Direct`) or from an `X-Forwarded-Client-Cert` header
(`mtls.Header`, RFC 9440 / Envoy / nginx-ingress). The header path is
footgun-prone: the **ingress MUST strip any client-supplied
`X-Forwarded-Client-Cert`** before keyforge sees it. The required
ingress snippets for nginx and Envoy live in `docs/flows/mtls.md`.

Header-based mTLS is refused unless `security.trusted_proxies`
contains the ingress's CIDR; this is enforced at config validation
time, not at runtime.

## Secrets handling

| Secret | Storage | Wrapping |
| --- | --- | --- |
| User password | `user_credentials.password_hash` | argon2id (t=2, m=64 MiB, p=4) |
| JWKS private key | `jwks_keys.private_pem_ciphertext` | DEK + KEK (envelope) |
| TOTP secret | `user_mfa_totp.secret_ciphertext` | DEK + KEK (envelope) |
| Upstream IdP secret | `idp_connectors.secret_ciphertext` | DEK + KEK (envelope) |
| Recovery code | `user_recovery_codes.code_hash` | bcrypt (cost 12) |
| OAuth client secret | `clients.client_secret_hash` | bcrypt (cost 12) |
| Refresh token | `refresh_tokens.token_hash` | SHA-256 |
| Access token | `access_tokens.token_hash` | SHA-256 |
| Authorization code | `auth_requests.code_hash` | SHA-256 |

The KEK comes from `KEYFORGE_JWKS__MASTER_KEY` (32-byte secret, base64
/ hex / raw). Compromise of the KEK + DB implies compromise of every
sealed secret; keep the KEK outside the DB's blast radius (SealedSecrets,
Vault, Secrets Manager).

## Vulnerability reporting

Email `security@keyforge.example`. Please do not file public GitHub
issues for unpatched vulnerabilities.
