# Changelog

All notable changes to keyforge are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **M0** — Repo scaffolding: Go module, Makefile, golangci-lint config, CI
  skeleton, license, README, version package.
- **M1** — Config (koanf), structured logging (slog + redaction), HTTP boot
  with chi + otelhttp.
- **M2** — Postgres + pgx/sqlc + multi-tenant storage; `tenantguard_test`
  build-time check.
- **M3** — JWKS store + signer + 90d/30d rotation worker.
- **M4** — Discovery, clients CRUD, all 5 client-auth methods (none,
  client_secret_basic, client_secret_post, private_key_jwt,
  tls_client_auth, self_signed_tls_client_auth).
- **M5** — Authorization Code + PKCE, server-rendered login/consent.
- **M6** — Hybrid token endpoint, refresh rotation + reuse detection,
  introspection, revocation, UserInfo.
- **M7** — Client Credentials grant + scope/resource policy.
- **M8** — PAR (RFC 9126) + JAR (RFC 9101).
- **M9** — JARM JWT-secured authorization responses.
- **M10** — DPoP proofs, replay cache, optional `DPoP-Nonce`.
- **M11** — mTLS certificate-bound tokens (RFC 8705 §3).
- **M12** — Device Authorization Flow (RFC 8628).
- **M13** — CIBA poll mode.
- **M14** — MFA: TOTP, WebAuthn (passkeys), single-use recovery codes.
- **M15** — Upstream OIDC federation (coreos/go-oidc).
- **M16** — Admin REST API + RBAC + append-only audit log.
- **M17** — React SPA scaffolding + Go embed mount + keyforge-spa seed.
- **M18** — User portal API + pages + soft-delete + hard-delete worker.
- **M19** — Admin console pages (clients, users, audit).
- **M20** — Observability: keyforge_* Prometheus metrics + redaction
  enumeration tests.
- **M21** — Rate limiting + brute-force lockout (memory + Postgres
  backends).
- **M22** — Docker Compose dev environment with step-ca + Dockerfile +
  hot-reload.
- **M23** — Helm chart + Kustomize overlays.
- **M24** — CI pipeline (lint, unit, integration, vuln, trivy, SBOM,
  helm-lint) + nightly conformance + release workflow with cosign
  keyless signing.
- **M25** — Documentation set: README, architecture, operations,
  security, per-flow guides.

## [0.1.0] — TBD

First tagged release. Awaits the verification plan documented in the
planning doc (unit + integration + compose smoke + Playwright + OIDF
conformance + kind cluster deploy + performance + security drills +
supply chain + docs validation).
