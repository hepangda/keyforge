-- seed-demo-client.sql — register the local demo relying party as an OAuth client.
--
-- Apply to the LOCAL D1 used by `wrangler dev` (never production):
--   wrangler d1 execute keyforge --local --file=examples/demo-app/seed-demo-client.sql
--
-- Public client + PKCE (no secret), callback on the demo app's localhost port.
-- Idempotent: re-running replaces the row.

DELETE FROM oauth_clients WHERE client_id = 'demo_local';

INSERT INTO oauth_clients (
  client_id, client_secret_hash, type, client_kind, name,
  redirect_uris_json, post_logout_redirect_uris_json,
  allowed_scopes_json, allowed_grant_types_json,
  allowed_resources_json, default_resource, require_pkce, enabled,
  token_endpoint_auth_methods_json, created_at, updated_at
) VALUES (
  'demo_local', NULL, 'public', 'application', 'Local Demo App',
  '["http://localhost:8788/callback"]',
  '["http://localhost:8788/"]',
  '["openid","profile","email","offline_access","api.read"]',
  '["authorization_code","refresh_token"]',
  '["https://api.pangda.app"]',
  'https://api.pangda.app', 1, 1, '["none"]', unixepoch(), unixepoch()
);

INSERT INTO oauth_client_permission_groups (client_id, group_id, created_at)
SELECT 'demo_local', id, unixepoch()
FROM groups
WHERE id = 'grp_seed_employees';

DELETE FROM permission_group_rules
WHERE id IN ('prule_demo_local_base', 'prule_demo_local_read');

WITH next_position AS (
  SELECT COALESCE(MAX(position) + 1, 0) AS value
  FROM permission_group_rules
  WHERE group_id = 'grp_seed_employees'
)
INSERT INTO permission_group_rules
  (id, group_id, effect, condition_json, position, created_at, updated_at)
SELECT
  'prule_demo_local_base', 'grp_seed_employees', 'allow',
  '{"operator":"and","conditions":[{"field":"application","operator":"equals","value":"demo_local"},{"field":"api","operator":"equals","value":"https://api.pangda.app"}]}',
  next_position.value, unixepoch(), unixepoch()
FROM next_position
UNION ALL
SELECT
  'prule_demo_local_read', 'grp_seed_employees', 'allow',
  '{"operator":"and","conditions":[{"field":"application","operator":"equals","value":"demo_local"},{"field":"api","operator":"equals","value":"https://api.pangda.app"},{"field":"scope","operator":"equals","value":"api.read"}]}',
  next_position.value + 1, unixepoch(), unixepoch()
FROM next_position;
