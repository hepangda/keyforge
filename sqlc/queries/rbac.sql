-- tenantguard: global-ok (roles is the global role catalog, not tenant-scoped)
-- name: ListRoles :many
SELECT * FROM roles
ORDER BY name ASC;

-- tenantguard: global-ok (lookup-by-name on global role catalog)
-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = $1;

-- name: GrantRole :exec
INSERT INTO user_roles (tenant_id, user_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING;

-- name: RevokeRole :exec
DELETE FROM user_roles
WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3;

-- name: ListRolesForUser :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.tenant_id = $1 AND ur.user_id = $2
ORDER BY r.name ASC;

-- name: ListUsersInRole :many
SELECT u.* FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r       ON r.id = ur.role_id
WHERE ur.tenant_id = $1 AND r.name = $2
ORDER BY u.email ASC;
