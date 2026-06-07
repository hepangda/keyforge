-- 0012_rbac: roles + role assignments.
--
-- Three seeded roles cover keyforge's authorization needs:
--   admin         — cross-tenant operator (only assignable for the bootstrap tenant)
--   tenant_admin  — full admin within one tenant
--   user          — end-user; no admin permissions
--
-- The (user_id, role_id, tenant_id) triple is unique so a user can hold
-- different roles in different tenants — useful for users who manage
-- multiple tenants from one account.

BEGIN;

CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    -- permissions is a flat list of strings like "clients:read", "users:write".
    permissions TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (name, description, permissions) VALUES
    ('admin',        'Cross-tenant operator', ARRAY[
        'tenants:read','tenants:write',
        'clients:read','clients:write',
        'users:read','users:write',
        'sessions:read','sessions:write',
        'audit:read',
        'scopes:read','scopes:write',
        'idp:read','idp:write'
    ]),
    ('tenant_admin', 'Tenant administrator', ARRAY[
        'clients:read','clients:write',
        'users:read','users:write',
        'sessions:read','sessions:write',
        'audit:read',
        'scopes:read','scopes:write',
        'idp:read','idp:write'
    ]),
    ('user',         'End user', ARRAY[]::TEXT[]);

CREATE TABLE user_roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, role_id, tenant_id)
);

CREATE INDEX user_roles_tenant_idx ON user_roles(tenant_id);
CREATE INDEX user_roles_user_idx ON user_roles(user_id);

UPDATE schema_meta SET version = '0012_rbac', applied_at = NOW();

COMMIT;
