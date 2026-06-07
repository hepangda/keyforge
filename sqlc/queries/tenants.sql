-- name: CreateTenant :one
INSERT INTO tenants (slug, display_name, issuer)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetTenantByID :one
SELECT * FROM tenants
WHERE id = $1;

-- name: GetTenantBySlug :one
SELECT * FROM tenants
WHERE slug = $1;

-- name: GetTenantByIssuer :one
SELECT * FROM tenants
WHERE issuer = $1;

-- name: ListTenants :many
SELECT * FROM tenants
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateTenant :one
UPDATE tenants
SET display_name = $2,
    issuer       = $3,
    enabled      = $4,
    updated_at   = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteTenant :exec
DELETE FROM tenants
WHERE id = $1;
