-- 0004_sessions_authrequests: browser session, in-flight authorization
-- requests (incl PAR/JAR fields), and recorded user consents.

BEGIN;

-- ---------------------------------------------------------------------------
-- sessions: the server-side projection of a __Host-kf_sid cookie. Holds
-- mfa_level, IP/UA fingerprint, last seen time.
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    csrf_secret   TEXT        NOT NULL,
    ip            TEXT,
    user_agent    TEXT,
    mfa_level     TEXT        NOT NULL DEFAULT 'pwd',
    amr           TEXT[]      NOT NULL DEFAULT ARRAY['pwd']::TEXT[],
    auth_time     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX sessions_tenant_user_idx ON sessions(tenant_id, user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

-- ---------------------------------------------------------------------------
-- auth_requests: an in-flight OAuth/OIDC authorization request, persisted
-- so that the user can step through login + MFA + consent without losing
-- the original parameters. Authorization codes are stored hashed in `code`.
-- ---------------------------------------------------------------------------
CREATE TABLE auth_requests (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id                UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri             TEXT        NOT NULL,
    response_type            TEXT        NOT NULL,
    response_mode            TEXT,
    scopes                   TEXT[]      NOT NULL,
    state                    TEXT,
    nonce                    TEXT,
    code_challenge           TEXT,
    code_challenge_method    TEXT,
    prompt                   TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    max_age                  INTEGER,
    ui_locales               TEXT,
    acr_values               TEXT,
    login_hint               TEXT,
    -- PAR / JAR provenance for later milestones
    par_request_uri          TEXT,
    request_object_jti       TEXT,
    -- Session that fulfilled this request (set after login completes)
    login_session_id         UUID REFERENCES sessions(id) ON DELETE SET NULL,
    user_id                  UUID REFERENCES users(id)    ON DELETE SET NULL,
    -- Authorization code, sha256-hashed (hex). Issued at consent time.
    code_hash                TEXT,
    code_issued_at           TIMESTAMPTZ,
    code_consumed_at         TIMESTAMPTZ,
    consented_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMPTZ NOT NULL
);

CREATE INDEX auth_requests_tenant_idx ON auth_requests(tenant_id);
CREATE INDEX auth_requests_code_hash_idx ON auth_requests(code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX auth_requests_expires_idx ON auth_requests(expires_at);

-- ---------------------------------------------------------------------------
-- user_consents: a user's standing approval of a (client, scope-set) pair.
-- Re-presenting the same scopes for the same client skips the consent
-- screen unless `prompt=consent` was requested.
-- ---------------------------------------------------------------------------
CREATE TABLE user_consents (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    client_id   UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes      TEXT[]      NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX user_consents_unique_active_idx
    ON user_consents(tenant_id, user_id, client_id)
    WHERE revoked_at IS NULL;

UPDATE schema_meta SET version = '0004_sessions_authrequests', applied_at = NOW();

COMMIT;
