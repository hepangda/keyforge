-- name: InsertPARRequest :one
INSERT INTO par_requests (tenant_id, request_uri, client_id, payload, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetPARRequest :one
SELECT * FROM par_requests
WHERE request_uri = $1
  AND tenant_id   = $2
FOR UPDATE;

-- name: MarkPARRequestConsumed :exec
UPDATE par_requests
SET consumed_at = NOW()
WHERE id = $1
  AND tenant_id = $2
  AND consumed_at IS NULL;

-- name: DeleteExpiredPARRequests :exec
-- tenantguard: global-ok (background sweep across tenants; status-driven)
DELETE FROM par_requests
WHERE expires_at < $1;
