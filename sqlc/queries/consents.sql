-- name: UpsertUserConsent :exec
INSERT INTO user_consents (tenant_id, user_id, client_id, scopes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, user_id, client_id) WHERE revoked_at IS NULL
DO UPDATE SET
    scopes     = EXCLUDED.scopes,
    granted_at = NOW();

-- name: GetActiveUserConsent :one
SELECT * FROM user_consents
WHERE tenant_id = $1
  AND user_id   = $2
  AND client_id = $3
  AND revoked_at IS NULL
ORDER BY granted_at DESC
LIMIT 1;

-- name: ListUserConsents :many
SELECT * FROM user_consents
WHERE tenant_id = $1
  AND user_id   = $2
  AND revoked_at IS NULL
ORDER BY granted_at DESC;

-- name: RevokeUserConsent :exec
UPDATE user_consents
SET revoked_at = NOW()
WHERE id = $1
  AND tenant_id = $2;
