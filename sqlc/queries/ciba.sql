-- name: InsertCIBARequest :one
INSERT INTO ciba_requests (
    tenant_id, client_id, auth_req_id, user_id, binding_message,
    scopes, audience, acr_values, interval_seconds, expires_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10
)
RETURNING *;

-- name: GetCIBAByAuthReqID :one
SELECT * FROM ciba_requests
WHERE auth_req_id = $1
  AND tenant_id   = $2
FOR UPDATE;

-- name: ListPendingCIBAForUser :many
SELECT * FROM ciba_requests
WHERE tenant_id = $1
  AND user_id   = $2
  AND status    = 'pending'
  AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: SetCIBAStatus :exec
UPDATE ciba_requests
SET status = $3
WHERE id = $1
  AND tenant_id = $2;

-- name: TouchCIBAPoll :exec
UPDATE ciba_requests
SET last_polled_at = NOW()
WHERE id = $1
  AND tenant_id = $2;
