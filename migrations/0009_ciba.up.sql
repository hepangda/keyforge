-- 0009_ciba: Client-Initiated Backchannel Authentication (poll mode).

BEGIN;

CREATE TABLE ciba_requests (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    auth_req_id     TEXT        NOT NULL UNIQUE,
    -- the user who must approve (resolved at /bc-authorize from login_hint
    -- or id_token_hint).
    user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
    binding_message TEXT,
    scopes          TEXT[]      NOT NULL,
    audience        TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    acr_values      TEXT,
    interval_seconds INTEGER    NOT NULL DEFAULT 5,
    last_polled_at  TIMESTAMPTZ,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','denied','expired','consumed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX ciba_requests_tenant_user_idx ON ciba_requests(tenant_id, user_id);
CREATE INDEX ciba_requests_expires_idx ON ciba_requests(expires_at);

UPDATE schema_meta SET version = '0009_ciba', applied_at = NOW();

COMMIT;
