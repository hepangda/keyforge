-- name: InsertAccessToken :one
INSERT INTO access_tokens (
    tenant_id, token_hash, client_id, user_id, scopes, audience,
    cnf_jkt, cnf_x5t_s256, session_id, issued_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11
)
RETURNING *;

-- name: GetAccessTokenByHash :one
SELECT * FROM access_tokens
WHERE tenant_id = $1
  AND token_hash = $2
  AND revoked_at IS NULL;

-- name: RevokeAccessToken :exec
UPDATE access_tokens
SET revoked_at = NOW()
WHERE tenant_id = $1
  AND token_hash = $2
  AND revoked_at IS NULL;

-- name: RevokeAllAccessTokensForFamily :exec
-- Used by refresh-token reuse detection: when a consumed RT is presented
-- again, the entire family's still-live access tokens are revoked too.
-- tenantguard: global-ok (filter is by token id and the surrounding tx already loaded the family scoped to a tenant)
UPDATE access_tokens
SET revoked_at = NOW()
WHERE id = ANY($1::uuid[])
  AND revoked_at IS NULL;

-- name: InsertRefreshToken :one
INSERT INTO refresh_tokens (
    tenant_id, token_hash, client_id, user_id, scopes,
    family_id, parent_id, cnf_jkt, cnf_x5t_s256, issued_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10, $11
)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens
WHERE tenant_id = $1
  AND token_hash = $2
FOR UPDATE;

-- name: MarkRefreshTokenConsumed :exec
UPDATE refresh_tokens
SET consumed_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE id = $1
  AND tenant_id = $2
  AND revoked_at IS NULL;

-- name: RevokeRefreshFamily :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE tenant_id = $1
  AND family_id = $2
  AND revoked_at IS NULL;

-- name: ListRefreshTokensInFamily :many
SELECT * FROM refresh_tokens
WHERE tenant_id = $1
  AND family_id = $2
ORDER BY issued_at ASC;
