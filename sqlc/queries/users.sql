-- name: CreateUser :one
INSERT INTO users (tenant_id, email, email_verified, display_name, locale, zoneinfo)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1
  AND tenant_id = $2
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE tenant_id = $1
  AND lower(email) = lower($2)
  AND deleted_at IS NULL;

-- name: ListUsersByTenant :many
SELECT * FROM users
WHERE tenant_id = $1
  AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateUser :one
UPDATE users
SET email          = $3,
    email_verified = $4,
    display_name   = $5,
    locale         = $6,
    zoneinfo       = $7,
    picture_url    = $8,
    enabled        = $9,
    updated_at     = NOW()
WHERE id = $1
  AND tenant_id = $2
RETURNING *;

-- name: SoftDeleteUser :exec
UPDATE users
SET deleted_at = NOW(),
    enabled    = FALSE,
    updated_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: UpsertUserCredentials :exec
INSERT INTO user_credentials (user_id, tenant_id, password_hash, algorithm, must_change)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    algorithm     = EXCLUDED.algorithm,
    must_change   = EXCLUDED.must_change,
    updated_at    = NOW();

-- name: GetUserCredentials :one
SELECT * FROM user_credentials
WHERE user_id = $1
  AND tenant_id = $2;
