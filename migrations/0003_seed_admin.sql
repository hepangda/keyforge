-- 0003_seed_admin.sql
--
-- Production credentials are intentionally not seeded. Create the first
-- administrator through POST /setup/bootstrap with the BOOTSTRAP_TOKEN secret.
-- Integration tests add their own isolated fixture in test/apply-migrations.ts.
SELECT 1;
