-- name: InsertJWKSKey :one
INSERT INTO jwks_keys (
    tenant_id, kid, alg, use, public_pem,
    private_ciphertext, dek_ciphertext, status,
    created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    $9
)
RETURNING *;

-- name: GetActiveJWKSKey :one
SELECT * FROM jwks_keys
WHERE (tenant_id = $1 OR tenant_id IS NULL)
  AND use = $2
  AND status = 'active'
ORDER BY tenant_id NULLS LAST, created_at DESC
LIMIT 1;

-- name: GetJWKSKeyByKID :one
-- tenantguard: global-ok (kid is a SHA-256 hash and globally unique by construction; verifiers may not know the tenant yet)
SELECT * FROM jwks_keys
WHERE kid = $1;

-- name: ListPublicJWKSKeys :many
SELECT * FROM jwks_keys
WHERE (tenant_id = $1 OR tenant_id IS NULL)
  AND status IN ('active', 'rotated')
ORDER BY created_at DESC;

-- name: ListAllJWKSKeys :many
SELECT * FROM jwks_keys
WHERE (tenant_id = $1 OR tenant_id IS NULL)
ORDER BY created_at DESC;

-- name: MarkJWKSKeyRotated :exec
-- tenantguard: global-ok (called inside Rotate's tx, key was just read by id with tenant filter applied)
UPDATE jwks_keys
SET status = 'rotated',
    rotated_at = $2
WHERE id = $1
  AND status = 'active';

-- name: RetireJWKSKeysOlderThan :exec
-- tenantguard: global-ok (background sweep across all tenants; status-driven, not tenant-driven)
UPDATE jwks_keys
SET status = 'retired',
    retired_at = $2
WHERE status = 'rotated'
  AND rotated_at IS NOT NULL
  AND rotated_at < $1;

-- name: DeleteRetiredJWKSKeys :exec
-- tenantguard: global-ok (background sweep across all tenants; status-driven, not tenant-driven)
DELETE FROM jwks_keys
WHERE status = 'retired'
  AND retired_at IS NOT NULL
  AND retired_at < $1;
