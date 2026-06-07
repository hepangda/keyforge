-- 0002_default_tenant: seed a bootstrap tenant on fresh installs.
-- Subsequent installations can disable this tenant; it exists so the binary
-- can boot without operator intervention.

BEGIN;

INSERT INTO tenants (id, slug, display_name, issuer)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default Tenant',
    'http://localhost:8080'
)
ON CONFLICT (id) DO NOTHING;

UPDATE schema_meta SET version = '0002_default_tenant', applied_at = NOW();

COMMIT;
