-- 0006_client_resources: per-client RFC 8707 resource indicators (audience
-- allowlist). Requested `resource` parameter values at the token / authorize
-- endpoints must be in this set for grants that issue access tokens.

BEGIN;

CREATE TABLE client_allowed_resources (
    id         BIGSERIAL   PRIMARY KEY,
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id  UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    resource   TEXT        NOT NULL,
    UNIQUE (client_id, resource)
);

CREATE INDEX client_allowed_resources_tenant_idx ON client_allowed_resources(tenant_id);

UPDATE schema_meta SET version = '0006_client_resources', applied_at = NOW();

COMMIT;
