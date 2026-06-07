-- 0001_init: tenants, users, credentials, clients, JWKS keys
-- All keyforge domain tables are tenant-scoped via tenant_id FK.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- tenants: top-level isolation boundary. Every row in every other table
-- references one. A bootstrap tenant is seeded by 0002.
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT        NOT NULL UNIQUE,
    display_name TEXT       NOT NULL,
    issuer      TEXT        NOT NULL UNIQUE,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- users: end-user accounts. The same email may exist across tenants, so the
-- uniqueness constraint is composite.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL,
    email_verified  BOOLEAN     NOT NULL DEFAULT FALSE,
    display_name    TEXT,
    locale          TEXT,
    zoneinfo        TEXT,
    picture_url     TEXT,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE (tenant_id, email)
);

CREATE INDEX users_tenant_idx ON users(tenant_id);
CREATE INDEX users_email_lower_idx ON users(tenant_id, lower(email));

-- ---------------------------------------------------------------------------
-- user_credentials: argon2id password hashes. Split from users so we can
-- support credential-less users (federation-only) and rotate hashes
-- independently.
-- ---------------------------------------------------------------------------
CREATE TABLE user_credentials (
    user_id        UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    password_hash  TEXT        NOT NULL,
    algorithm      TEXT        NOT NULL DEFAULT 'argon2id',
    must_change    BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_credentials_tenant_idx ON user_credentials(tenant_id);

-- ---------------------------------------------------------------------------
-- clients: OAuth/OIDC client registrations. client_id is unique per tenant
-- (so the same id can exist in different tenants without clashing).
-- ---------------------------------------------------------------------------
CREATE TABLE clients (
    id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id                   TEXT        NOT NULL,
    client_secret_hash          TEXT,
    client_type                 TEXT        NOT NULL CHECK (client_type IN ('public','confidential')),
    name                        TEXT        NOT NULL,
    description                 TEXT,
    -- Comma-separated would be the lazy choice; PG arrays are first-class.
    grant_types                 TEXT[]      NOT NULL DEFAULT ARRAY['authorization_code']::TEXT[],
    response_types              TEXT[]      NOT NULL DEFAULT ARRAY['code']::TEXT[],
    response_modes              TEXT[]      NOT NULL DEFAULT ARRAY['query']::TEXT[],
    scopes                      TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    token_endpoint_auth_method  TEXT        NOT NULL DEFAULT 'client_secret_basic',
    token_endpoint_auth_signing_alg TEXT,
    -- request object (JAR) signing
    request_object_signing_alg  TEXT,
    require_signed_request_object BOOLEAN   NOT NULL DEFAULT FALSE,
    -- PAR
    require_par                 BOOLEAN     NOT NULL DEFAULT FALSE,
    -- DPoP
    require_dpop                BOOLEAN     NOT NULL DEFAULT FALSE,
    dpop_bound_access_tokens    BOOLEAN     NOT NULL DEFAULT FALSE,
    -- mTLS
    tls_client_auth_subject_dn  TEXT,
    tls_client_certificate_bound_access_tokens BOOLEAN NOT NULL DEFAULT FALSE,
    -- JARM
    authorization_signed_response_alg TEXT,
    -- JWKS resolution
    jwks_uri                    TEXT,
    -- optional inline JWKS (jsonb of the full JWK Set)
    jwks                        JSONB,
    -- CIBA
    backchannel_token_delivery_mode TEXT,
    backchannel_client_notification_endpoint TEXT,
    -- federation
    is_federation_client        BOOLEAN     NOT NULL DEFAULT FALSE,
    -- audit
    enabled                     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, client_id)
);

CREATE INDEX clients_tenant_idx ON clients(tenant_id);

-- ---------------------------------------------------------------------------
-- client_redirect_uris: stored separately to keep exact-match validation
-- trivially indexable.
-- ---------------------------------------------------------------------------
CREATE TABLE client_redirect_uris (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   UUID        NOT NULL REFERENCES clients(id)  ON DELETE CASCADE,
    redirect_uri TEXT       NOT NULL,
    UNIQUE (client_id, redirect_uri)
);

CREATE INDEX client_redirect_uris_tenant_idx ON client_redirect_uris(tenant_id);

-- ---------------------------------------------------------------------------
-- jwks_keys: server signing keys. tenant_id is NULLABLE so that a global
-- key set can be shared across tenants; per-tenant override is allowed by
-- inserting rows with a non-NULL tenant_id.
-- ---------------------------------------------------------------------------
CREATE TABLE jwks_keys (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID                 REFERENCES tenants(id) ON DELETE CASCADE,
    kid                 TEXT        NOT NULL UNIQUE,
    alg                 TEXT        NOT NULL,
    use                 TEXT        NOT NULL DEFAULT 'sig',
    public_pem          TEXT        NOT NULL,
    private_ciphertext  BYTEA       NOT NULL,
    dek_ciphertext      BYTEA       NOT NULL,
    status              TEXT        NOT NULL CHECK (status IN ('active','rotated','retired')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at          TIMESTAMPTZ,
    retired_at          TIMESTAMPTZ
);

CREATE INDEX jwks_keys_tenant_status_idx ON jwks_keys(tenant_id, status);

-- ---------------------------------------------------------------------------
-- schema_meta: a single-row table used by /readyz to confirm migrations ran.
-- ---------------------------------------------------------------------------
CREATE TABLE schema_meta (
    singleton  BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version    TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_meta (version) VALUES ('0001_init');

COMMIT;
