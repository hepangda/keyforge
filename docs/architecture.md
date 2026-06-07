# Architecture

## C4 — System context

```mermaid
C4Context
  Person(user, "End user", "Signs in to a Relying Party")
  Person(admin, "Operator", "Manages tenants, clients, sessions")
  System(keyforge, "keyforge", "OAuth 2.1 / OIDC authorization server")
  System_Ext(rp, "Relying Party", "First- or third-party app")
  System_Ext(idp, "Upstream IdP", "Google, Okta, another keyforge")
  System_Ext(pg,  "Postgres", "Tenant + token state")
  Rel(user, rp, "Uses")
  Rel(rp, keyforge, "OAuth/OIDC")
  Rel(user, keyforge, "Login + consent")
  Rel(admin, keyforge, "Admin REST + UI")
  Rel(keyforge, idp, "Federated login (OIDC RP)")
  Rel(keyforge, pg, "pgx + sqlc")
```

## Container view

```mermaid
C4Container
  System_Boundary(kf, "keyforge") {
    Container(spa, "React SPA", "Vite/TS", "Portal + admin console")
    Container(public, "Public HTTP", "Go/chi", "/oauth/*, /.well-known/*, /portal/api/*")
    Container(admin, "Admin HTTP", "Go/chi", "/metrics, admin API")
    Container(workers, "Background workers", "Go", "JWKS rotation, hard-delete sweep")
  }
  ContainerDb(pg, "Postgres", "16", "Tenants, clients, tokens, audit")
  Rel(spa, public, "PKCE + REST")
  Rel(public, pg, "")
  Rel(admin, pg, "")
  Rel(workers, pg, "")
```

## Authorization Code + PKCE (sequence)

```mermaid
sequenceDiagram
  participant U as User
  participant RP as Relying Party
  participant K as keyforge
  participant DB as Postgres
  U->>RP: open app
  RP->>U: 302 /oauth/authorize?... (PKCE S256)
  U->>K: GET /oauth/authorize
  K->>DB: insert auth_request
  K->>U: render /oauth/login
  U->>K: POST credentials (+ MFA if enrolled)
  K->>K: open session, attach to auth_request
  K->>U: render /oauth/consent
  U->>K: allow
  K->>DB: persist consent, mint authorization code
  K->>RP: 302 redirect_uri?code=…&state=…
  RP->>K: POST /oauth/token (code + verifier)
  K->>DB: validate code, mint AT + RT (cnf_jkt if DPoP)
  K-->>RP: { access_token, id_token, refresh_token }
```

## Hybrid token model

- **Access tokens** are opaque (`kf_at_<base64url>`); SHA-256 hash stored
  in `access_tokens`. Instantly revocable.
- **ID tokens** are JWTs signed by the active JWKS key.
- **Refresh tokens** are opaque, rotated on every grant. Presenting a
  consumed RT (inside a SERIALIZABLE tx) revokes the entire family —
  proven by `tokens` integration test.

## Multi-tenancy

Every domain table carries `tenant_id`. The `internal/storage` package
exposes `postgres.ContextWithTenant` / `MustTenant`; the build-time
`tenantguard_test.go` fails any sqlc query that touches a tenant-owned
table without `WHERE tenant_id` (or the explicit `-- tenantguard:
global-ok` opt-out comment with a reason).
