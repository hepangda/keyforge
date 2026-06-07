-- name: CreateIdPConnector :one
INSERT INTO idp_connectors (
    tenant_id, slug, display_name, issuer, client_id,
    secret_ciphertext, dek_ciphertext, scopes, claim_mapping, enabled
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

-- name: GetIdPConnectorBySlug :one
SELECT * FROM idp_connectors
WHERE tenant_id = $1 AND slug = $2;

-- name: GetIdPConnectorByID :one
SELECT * FROM idp_connectors
WHERE id = $1 AND tenant_id = $2;

-- name: ListEnabledIdPConnectors :many
SELECT * FROM idp_connectors
WHERE tenant_id = $1 AND enabled = TRUE
ORDER BY display_name ASC;

-- name: DeleteIdPConnector :exec
DELETE FROM idp_connectors
WHERE id = $1 AND tenant_id = $2;

-- name: LinkFederatedIdentity :one
INSERT INTO federated_identity (
    tenant_id, idp_id, user_id, subject
) VALUES (
    $1, $2, $3, $4
)
ON CONFLICT (tenant_id, idp_id, subject) DO UPDATE SET
    last_login_at = NOW()
RETURNING *;

-- name: GetFederatedUser :one
SELECT * FROM federated_identity
WHERE tenant_id = $1 AND idp_id = $2 AND subject = $3;

-- name: ListFederatedIdentitiesForUser :many
SELECT fi.*, ic.slug AS idp_slug, ic.display_name AS idp_display_name
FROM federated_identity fi
JOIN idp_connectors ic ON ic.id = fi.idp_id
WHERE fi.tenant_id = $1 AND fi.user_id = $2
ORDER BY fi.linked_at DESC;

-- name: UnlinkFederatedIdentity :exec
DELETE FROM federated_identity
WHERE id = $1 AND tenant_id = $2;

-- name: SetAuthRequestFederation :exec
UPDATE auth_requests
SET federation_idp_id          = $3,
    federation_state           = $4,
    federation_nonce           = $5,
    federation_pkce_verifier   = $6
WHERE id = $1 AND tenant_id = $2;

-- name: GetAuthRequestByFederationState :one
SELECT * FROM auth_requests
WHERE tenant_id = $1 AND federation_state = $2;
