-- name: UpsertUserTOTP :exec
INSERT INTO user_mfa_totp (
    user_id, tenant_id, secret_ciphertext, dek_ciphertext,
    algorithm, digits, period_seconds
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
ON CONFLICT (user_id) DO UPDATE SET
    secret_ciphertext = EXCLUDED.secret_ciphertext,
    dek_ciphertext    = EXCLUDED.dek_ciphertext,
    algorithm         = EXCLUDED.algorithm,
    digits            = EXCLUDED.digits,
    period_seconds    = EXCLUDED.period_seconds,
    confirmed_at      = NULL,
    last_counter      = NULL;

-- name: GetUserTOTP :one
SELECT * FROM user_mfa_totp
WHERE user_id   = $1
  AND tenant_id = $2;

-- name: ConfirmUserTOTP :exec
UPDATE user_mfa_totp
SET confirmed_at = COALESCE(confirmed_at, NOW()),
    last_used_at = NOW(),
    last_counter = $3
WHERE user_id   = $1
  AND tenant_id = $2;

-- name: TouchUserTOTP :exec
UPDATE user_mfa_totp
SET last_used_at = NOW(),
    last_counter = $3
WHERE user_id   = $1
  AND tenant_id = $2;

-- name: DeleteUserTOTP :exec
DELETE FROM user_mfa_totp
WHERE user_id   = $1
  AND tenant_id = $2;

-- name: InsertWebAuthnCredential :one
INSERT INTO user_webauthn_credentials (
    tenant_id, user_id, credential_id, public_key, sign_count,
    aaguid, transports, attestation_type, nickname
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING *;

-- name: ListWebAuthnCredentialsForUser :many
SELECT * FROM user_webauthn_credentials
WHERE tenant_id = $1
  AND user_id   = $2
ORDER BY created_at DESC;

-- name: UpdateWebAuthnSignCount :exec
UPDATE user_webauthn_credentials
SET sign_count   = $3,
    last_used_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: DeleteWebAuthnCredential :exec
DELETE FROM user_webauthn_credentials
WHERE id = $1
  AND tenant_id = $2;

-- name: InsertWebAuthnChallenge :one
INSERT INTO webauthn_challenges (
    tenant_id, user_id, ceremony, session_data, expires_at
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: ConsumeWebAuthnChallenge :one
DELETE FROM webauthn_challenges
WHERE id = $1
  AND tenant_id = $2
RETURNING *;

-- name: InsertRecoveryCode :exec
INSERT INTO user_recovery_codes (tenant_id, user_id, code_hash)
VALUES ($1, $2, $3);

-- name: ConsumeRecoveryCode :one
UPDATE user_recovery_codes
SET used_at = NOW()
WHERE tenant_id = $1
  AND user_id   = $2
  AND code_hash = $3
  AND used_at IS NULL
RETURNING *;

-- name: ListActiveRecoveryCodes :many
SELECT * FROM user_recovery_codes
WHERE tenant_id = $1
  AND user_id   = $2
  AND used_at IS NULL
ORDER BY created_at ASC;

-- name: CountActiveRecoveryCodes :one
SELECT COUNT(*) FROM user_recovery_codes
WHERE tenant_id = $1
  AND user_id   = $2
  AND used_at IS NULL;

-- name: DeleteRecoveryCodesForUser :exec
DELETE FROM user_recovery_codes
WHERE tenant_id = $1
  AND user_id   = $2;
