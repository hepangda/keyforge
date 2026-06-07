-- name: InsertAuditEvent :one
INSERT INTO audit_log (
    tenant_id, actor_user_id, actor_client_id,
    action, target_type, target_id,
    ip, user_agent, request_id, attributes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

-- name: ListAuditEvents :many
SELECT * FROM audit_log
WHERE tenant_id = $1
  AND (sqlc.narg('action')::TEXT IS NULL OR action = sqlc.narg('action'))
  AND (sqlc.narg('actor')::UUID IS NULL OR actor_user_id = sqlc.narg('actor'))
  AND occurred_at < $2
ORDER BY occurred_at DESC
LIMIT $3;
