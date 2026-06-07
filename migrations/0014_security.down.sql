BEGIN;
DROP TABLE IF EXISTS account_lockouts;
DROP TABLE IF EXISTS login_failures;
DROP TABLE IF EXISTS rate_buckets;
COMMIT;
