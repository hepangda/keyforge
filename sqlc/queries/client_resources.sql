-- name: AddClientAllowedResource :exec
INSERT INTO client_allowed_resources (tenant_id, client_id, resource)
VALUES ($1, $2, $3)
ON CONFLICT (client_id, resource) DO NOTHING;

-- name: ListClientAllowedResources :many
SELECT resource FROM client_allowed_resources
WHERE tenant_id = $1
  AND client_id = $2
ORDER BY resource;

-- name: DeleteClientAllowedResource :exec
DELETE FROM client_allowed_resources
WHERE tenant_id = $1
  AND client_id = $2
  AND resource   = $3;

-- name: ReplaceClientAllowedResources :exec
DELETE FROM client_allowed_resources
WHERE tenant_id = $1
  AND client_id = $2;
