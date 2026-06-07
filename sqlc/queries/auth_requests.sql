-- name: CreateAuthRequest :one
INSERT INTO auth_requests (
    tenant_id, client_id, redirect_uri, response_type, response_mode,
    scopes, state, nonce, code_challenge, code_challenge_method,
    prompt, max_age, ui_locales, acr_values, login_hint,
    par_request_uri, request_object_jti, expires_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11, $12, $13, $14, $15,
    $16, $17, $18
)
RETURNING *;

-- name: GetAuthRequest :one
SELECT * FROM auth_requests
WHERE id = $1
  AND tenant_id = $2
  AND expires_at > NOW();

-- name: AttachAuthRequestSession :exec
UPDATE auth_requests
SET login_session_id = $3,
    user_id          = $4
WHERE id = $1
  AND tenant_id = $2;

-- name: MarkAuthRequestConsentedAndCode :exec
UPDATE auth_requests
SET consented_at   = NOW(),
    code_hash      = $3,
    code_issued_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: GetAuthRequestByCodeHash :one
SELECT * FROM auth_requests
WHERE code_hash = $1
  AND tenant_id = $2;

-- name: MarkAuthRequestCodeConsumed :exec
UPDATE auth_requests
SET code_consumed_at = NOW()
WHERE id = $1
  AND tenant_id = $2
  AND code_consumed_at IS NULL;
