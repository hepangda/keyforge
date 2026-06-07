-- name: InsertDeviceCode :one
INSERT INTO device_codes (
    tenant_id, client_id, device_code, user_code, scopes, audience,
    interval_seconds, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING *;

-- name: GetDeviceCodeByDeviceCode :one
SELECT * FROM device_codes
WHERE device_code = $1
  AND tenant_id   = $2
FOR UPDATE;

-- name: GetDeviceCodeByUserCode :one
SELECT * FROM device_codes
WHERE user_code = $1
  AND tenant_id = $2
FOR UPDATE;

-- name: TouchDeviceCodePoll :exec
UPDATE device_codes
SET last_polled_at = NOW()
WHERE id = $1
  AND tenant_id = $2;

-- name: ApproveDeviceCode :exec
UPDATE device_codes
SET approved = TRUE,
    user_id  = $3
WHERE id = $1
  AND tenant_id = $2
  AND approved = FALSE
  AND denied   = FALSE;

-- name: DenyDeviceCode :exec
UPDATE device_codes
SET denied = TRUE
WHERE id = $1
  AND tenant_id = $2
  AND approved = FALSE
  AND denied   = FALSE;

-- name: RedeemDeviceCode :exec
UPDATE device_codes
SET redeemed_at = NOW()
WHERE id = $1
  AND tenant_id = $2
  AND redeemed_at IS NULL;
