-- name: CreateClient :one
INSERT INTO clients (
    tenant_id, client_id, client_secret_hash, client_type, name, description,
    grant_types, response_types, response_modes, scopes,
    token_endpoint_auth_method, token_endpoint_auth_signing_alg,
    request_object_signing_alg, require_signed_request_object,
    require_par, require_dpop, dpop_bound_access_tokens,
    tls_client_auth_subject_dn, tls_client_certificate_bound_access_tokens,
    authorization_signed_response_alg,
    jwks_uri, jwks,
    backchannel_token_delivery_mode, backchannel_client_notification_endpoint,
    is_federation_client
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12,
    $13, $14,
    $15, $16, $17,
    $18, $19,
    $20,
    $21, $22,
    $23, $24,
    $25
)
RETURNING *;

-- name: GetClientByID :one
SELECT * FROM clients
WHERE id = $1
  AND tenant_id = $2;

-- name: GetClientByClientID :one
SELECT * FROM clients
WHERE tenant_id = $1
  AND client_id = $2;

-- name: ListClientsByTenant :many
SELECT * FROM clients
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateClient :one
UPDATE clients
SET name                                       = $3,
    description                                = $4,
    grant_types                                = $5,
    response_types                             = $6,
    response_modes                             = $7,
    scopes                                     = $8,
    token_endpoint_auth_method                 = $9,
    token_endpoint_auth_signing_alg            = $10,
    request_object_signing_alg                 = $11,
    require_signed_request_object              = $12,
    require_par                                = $13,
    require_dpop                               = $14,
    dpop_bound_access_tokens                   = $15,
    tls_client_auth_subject_dn                 = $16,
    tls_client_certificate_bound_access_tokens = $17,
    authorization_signed_response_alg          = $18,
    jwks_uri                                   = $19,
    jwks                                       = $20,
    backchannel_token_delivery_mode            = $21,
    backchannel_client_notification_endpoint   = $22,
    enabled                                    = $23,
    updated_at                                 = NOW()
WHERE id = $1
  AND tenant_id = $2
RETURNING *;

-- name: RotateClientSecret :exec
UPDATE clients
SET client_secret_hash = $3,
    updated_at         = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: DeleteClient :exec
DELETE FROM clients
WHERE id = $1
  AND tenant_id = $2;

-- name: AddClientRedirectURI :exec
INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri)
VALUES ($1, $2, $3)
ON CONFLICT (client_id, redirect_uri) DO NOTHING;

-- name: ListClientRedirectURIs :many
SELECT redirect_uri FROM client_redirect_uris
WHERE tenant_id = $1
  AND client_id = $2
ORDER BY redirect_uri;

-- name: DeleteClientRedirectURI :exec
DELETE FROM client_redirect_uris
WHERE tenant_id = $1
  AND client_id = $2
  AND redirect_uri = $3;

-- name: ReplaceClientRedirectURIs :exec
DELETE FROM client_redirect_uris
WHERE tenant_id = $1
  AND client_id = $2;
