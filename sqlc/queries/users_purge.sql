-- name: HardDeleteExpiredUsers :execrows
-- tenantguard: global-ok (background sweep across all tenants; deletes by deleted_at age)
DELETE FROM users
WHERE deleted_at IS NOT NULL
  AND deleted_at < $1;
