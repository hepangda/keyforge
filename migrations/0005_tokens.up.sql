-- 0005_tokens: opaque access tokens and rotation-tracked refresh tokens.
-- Hybrid token strategy: AT is opaque (sha256-hashed at rest, instantly
-- revocable); ID token is a JWT signed via JWKS (not stored here). RT is
-- opaque, rotated on use, with reuse detection by family_id.

BEGIN;

CREATE TABLE access_tokens (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash        TEXT        NOT NULL,
    client_id         UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id           UUID        REFERENCES users(id) ON DELETE CASCADE,
    scopes            TEXT[]      NOT NULL,
    audience          TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    cnf_jkt           TEXT,       -- DPoP thumbprint when token is sender-constrained
    cnf_x5t_s256      TEXT,       -- mTLS cert thumbprint when cert-bound
    session_id        UUID        REFERENCES sessions(id) ON DELETE SET NULL,
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ
);

CREATE UNIQUE INDEX access_tokens_hash_active_idx
    ON access_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX access_tokens_tenant_idx ON access_tokens(tenant_id);
CREATE INDEX access_tokens_expires_idx ON access_tokens(expires_at);

CREATE TABLE refresh_tokens (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash        TEXT        NOT NULL,
    client_id         UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes            TEXT[]      NOT NULL,
    family_id         UUID        NOT NULL,
    parent_id         UUID        REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    cnf_jkt           TEXT,
    cnf_x5t_s256      TEXT,
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ
);

CREATE UNIQUE INDEX refresh_tokens_hash_active_idx
    ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX refresh_tokens_tenant_idx ON refresh_tokens(tenant_id);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);

UPDATE schema_meta SET version = '0005_tokens', applied_at = NOW();

COMMIT;
