-- 0008_device: Device Authorization Grant (RFC 8628).

BEGIN;

CREATE TABLE device_codes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    device_code     TEXT        NOT NULL UNIQUE,
    user_code       TEXT        NOT NULL UNIQUE,
    scopes          TEXT[]      NOT NULL,
    audience        TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    interval_seconds INTEGER    NOT NULL DEFAULT 5,
    last_polled_at  TIMESTAMPTZ,
    user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
    approved        BOOLEAN     NOT NULL DEFAULT FALSE,
    denied          BOOLEAN     NOT NULL DEFAULT FALSE,
    redeemed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX device_codes_tenant_idx ON device_codes(tenant_id);
CREATE INDEX device_codes_expires_idx ON device_codes(expires_at);

UPDATE schema_meta SET version = '0008_device', applied_at = NOW();

COMMIT;
