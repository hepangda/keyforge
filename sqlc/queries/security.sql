-- name: RecordLoginFailure :exec
-- tenantguard: global-ok (deliberate per-tenant insert, tenant_id pinned in params)
INSERT INTO login_failures (tenant_id, email_hash, ip)
VALUES ($1, $2, $3);

-- name: CountRecentLoginFailures :one
-- tenantguard: global-ok (tenant_id pinned in params)
SELECT COUNT(*) FROM login_failures
WHERE tenant_id = $1
  AND email_hash = $2
  AND occurred_at > $3;

-- name: ClearLoginFailures :exec
-- tenantguard: global-ok (tenant_id pinned in params)
DELETE FROM login_failures
WHERE tenant_id = $1 AND email_hash = $2;

-- name: UpsertLockout :exec
-- tenantguard: global-ok (tenant_id pinned in params)
INSERT INTO account_lockouts (tenant_id, email_hash, unlock_at, reason)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, email_hash) DO UPDATE
SET unlock_at = EXCLUDED.unlock_at,
    reason    = EXCLUDED.reason,
    locked_at = NOW();

-- name: GetActiveLockout :one
-- tenantguard: global-ok (tenant_id pinned in params)
SELECT * FROM account_lockouts
WHERE tenant_id = $1
  AND email_hash = $2
  AND unlock_at > NOW();

-- name: DeleteLockout :exec
-- tenantguard: global-ok (tenant_id pinned in params)
DELETE FROM account_lockouts
WHERE tenant_id = $1 AND email_hash = $2;

-- name: UpsertRateBucket :one
-- tenantguard: global-ok (rate_buckets is not tenant-scoped; key is opaque)
INSERT INTO rate_buckets (endpoint, key, level)
VALUES ($1, $2, $3)
ON CONFLICT (endpoint, key) DO UPDATE
SET level      = EXCLUDED.level,
    updated_at = NOW()
RETURNING *;

-- name: GetRateBucket :one
-- tenantguard: global-ok (rate_buckets is not tenant-scoped)
SELECT * FROM rate_buckets WHERE endpoint = $1 AND key = $2;
