-- 0014_security: rate-limit buckets + login-failure tracking.
--
-- rate_buckets:      one row per (endpoint, key) tuple holding the
--                    leaky-bucket level used by the PostgresLeakyBucket
--                    limiter. Memory limiters never touch this table.
-- login_failures:    one row per failed /oauth/login attempt; keyed on
--                    (tenant_id, email_hash) so we don't enumerate
--                    users by tracking by raw email.
-- account_lockouts:  active lockouts. A row exists for a given
--                    (tenant_id, email_hash) only while it is locked
--                    out; admin Unlock deletes the row.

BEGIN;

CREATE TABLE rate_buckets (
    endpoint    TEXT        NOT NULL,
    key         TEXT        NOT NULL,
    level       DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (endpoint, key)
);

CREATE TABLE login_failures (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email_hash  BYTEA       NOT NULL,
    ip          TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX login_failures_lookup_idx ON login_failures(tenant_id, email_hash, occurred_at DESC);

CREATE TABLE account_lockouts (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email_hash  BYTEA       NOT NULL,
    locked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unlock_at   TIMESTAMPTZ NOT NULL,
    reason      TEXT        NOT NULL DEFAULT 'too_many_failures',
    PRIMARY KEY (tenant_id, email_hash)
);

UPDATE schema_meta SET version = '0014_security', applied_at = NOW();

COMMIT;
