-- 0007_par: Pushed Authorization Requests (RFC 9126).

BEGIN;

CREATE TABLE par_requests (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_uri  TEXT        NOT NULL UNIQUE,
    client_id    UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    payload      JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ
);

CREATE INDEX par_requests_tenant_idx ON par_requests(tenant_id);
CREATE INDEX par_requests_expires_idx ON par_requests(expires_at);

UPDATE schema_meta SET version = '0007_par', applied_at = NOW();

COMMIT;
