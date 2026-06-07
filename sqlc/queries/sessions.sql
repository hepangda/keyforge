-- name: CreateSession :one
INSERT INTO sessions (
    tenant_id, user_id, csrf_secret, ip, user_agent,
    mfa_level, amr, auth_time, expires_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9
)
RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions
WHERE id = $1
  AND tenant_id = $2
  AND revoked_at IS NULL
  AND expires_at > NOW();

-- name: TouchSession :exec
UPDATE sessions
SET last_seen_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: RevokeSession :exec
UPDATE sessions
SET revoked_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: ListSessionsByUser :many
SELECT * FROM sessions
WHERE tenant_id = $1
  AND user_id = $2
  AND revoked_at IS NULL
  AND expires_at > NOW()
ORDER BY last_seen_at DESC;

-- name: RevokeAllSessionsForUser :exec
UPDATE sessions
SET revoked_at = NOW()
WHERE tenant_id = $1
  AND user_id = $2
  AND revoked_at IS NULL;

-- name: UpgradeSessionMFA :exec
UPDATE sessions
SET mfa_level   = $3,
    amr         = $4,
    last_seen_at = NOW()
WHERE id = $1
  AND tenant_id = $2;
