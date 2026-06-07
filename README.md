# keyforge

[![CI](https://github.com/hepangda/keyforge/actions/workflows/ci.yml/badge.svg)](https://github.com/hepangda/keyforge/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/hepangda/keyforge.svg)](https://pkg.go.dev/github.com/hepangda/keyforge)

**keyforge** is a production-grade, multi-tenant OAuth 2.1 / OpenID Connect authorization server written in Go.

It ships the full advanced-spec surface in v1:

- OAuth 2.1 Authorization Code with mandatory PKCE (S256)
- Refresh Token rotation with reuse detection
- Client Credentials, Device Authorization Flow, CIBA (poll mode)
- Token Introspection (RFC 7662), Token Revocation (RFC 7009), UserInfo
- Discovery (`/.well-known/openid-configuration`), JWKS rotation
- Pushed Authorization Requests / **PAR** (RFC 9126)
- JWT-Secured Authorization Request / **JAR** (RFC 9101)
- JWT-Secured Authorization Response Mode / **JARM**
- Demonstrating Proof of Possession / **DPoP** (RFC 9449)
- Mutual TLS client authentication + **certificate-bound access tokens** (RFC 8705)
- All five client authentication methods: `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`
- Multi-tenant from day one
- MFA: TOTP and WebAuthn passkeys, with recovery codes
- Upstream OIDC federation
- Admin REST API + user self-service portal (single React + TypeScript SPA)
- Append-only audit log, Prometheus metrics, OpenTelemetry tracing, slog structured logs

## Quick start (Docker Compose)

```bash
make compose-up      # postgres + mailhog + step-ca + keyforge
make compose-logs    # tail logs while it boots
./scripts/seed.sh    # print demo tenant + admin + client credentials
open http://localhost:8080
```

Stop and remove all volumes:

```bash
make compose-down
```

## Local development

```bash
make build           # compile bin/keyforge
make test            # unit tests with race detector
make test-integration  # integration tests (uses testcontainers-go Postgres)
make lint            # golangci-lint
make vuln            # govulncheck
make e2e             # Playwright browser tests
make e2e-shell       # curl-based shell smoke tests
```

See [docs/architecture.md](docs/architecture.md), [docs/operations.md](docs/operations.md),
and [docs/security.md](docs/security.md) for the longer story.

## Deployment

A production-grade Helm chart lives at [deploy/helm/keyforge](deploy/helm/keyforge),
with Kustomize overlays for dev/staging/prod under [deploy/kustomize](deploy/kustomize).

## License

Apache-2.0 — see [LICENSE](LICENSE).
