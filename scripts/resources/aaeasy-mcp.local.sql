-- Environment-owned AAEasy MCP authorization objects for local development.
INSERT INTO oauth_resources
  (resource_uri, name, allowed_scopes_json, enabled, mcp_enabled,
   allow_metadata_clients, metadata_client_policy, created_at, updated_at)
VALUES
  ('http://localhost:5173/mcp', 'AAEasy MCP (Local)',
   '["mcp.tools.read","mcp.tools.execute"]', 1, 1, 0,
   'consent_required', unixepoch(), unixepoch())
ON CONFLICT(resource_uri) DO UPDATE SET
  name = excluded.name,
  allowed_scopes_json = excluded.allowed_scopes_json,
  enabled = 1,
  mcp_enabled = 1,
  allow_metadata_clients = 0,
  metadata_client_policy = 'consent_required',
  updated_at = unixepoch();

INSERT INTO oauth_clients
  (client_id, client_secret_hash, type, client_kind, name,
   redirect_uris_json, post_logout_redirect_uris_json, allowed_scopes_json,
   allowed_grant_types_json, allowed_resources_json, default_resource,
   require_pkce, enabled, registration_type, metadata_expires_at,
   metadata_fingerprint, token_endpoint_auth_methods_json, metadata_jwks_uri,
   introspection_allowed, created_at, updated_at)
VALUES
  ('aaeasy_mcp_introspector', NULL, 'confidential', 'service',
   'AAEasy MCP introspector', '[]', '[]', '[]', '[]',
   '["http://localhost:5173/mcp"]', 'http://localhost:5173/mcp',
   1, 1, 'static', NULL, NULL,
   '["client_secret_basic","client_secret_post"]', NULL, 1,
   unixepoch(), unixepoch())
ON CONFLICT(client_id) DO UPDATE SET
  type = 'confidential',
  client_kind = 'service',
  name = excluded.name,
  redirect_uris_json = '[]',
  post_logout_redirect_uris_json = '[]',
  allowed_scopes_json = '[]',
  allowed_grant_types_json = '[]',
  allowed_resources_json = excluded.allowed_resources_json,
  default_resource = excluded.default_resource,
  require_pkce = 1,
  enabled = 1,
  registration_type = 'static',
  token_endpoint_auth_methods_json = excluded.token_endpoint_auth_methods_json,
  introspection_allowed = 1,
  updated_at = unixepoch();

-- Clean cutover from the historical service identity. Preserve its secret,
-- move live foreign-key state, then let client-delete triggers prune obsolete
-- permission rules. Audit history intentionally keeps the historical actor ID.
UPDATE oauth_clients
SET client_secret_hash = COALESCE(
  client_secret_hash,
  (SELECT client_secret_hash FROM oauth_clients WHERE client_id = 'aaeasy_mcp_resource_server')
)
WHERE client_id = 'aaeasy_mcp_introspector';
UPDATE OR IGNORE consents SET client_id = 'aaeasy_mcp_introspector'
WHERE client_id = 'aaeasy_mcp_resource_server';
UPDATE OR IGNORE refresh_tokens SET client_id = 'aaeasy_mcp_introspector'
WHERE client_id = 'aaeasy_mcp_resource_server';
UPDATE OR IGNORE authorization_grants SET client_id = 'aaeasy_mcp_introspector'
WHERE client_id = 'aaeasy_mcp_resource_server';
UPDATE OR IGNORE device_authorization_sessions SET client_id = 'aaeasy_mcp_introspector'
WHERE client_id = 'aaeasy_mcp_resource_server';
INSERT OR IGNORE INTO oauth_client_permission_groups (client_id, group_id, created_at)
SELECT 'aaeasy_mcp_introspector', group_id, created_at
FROM oauth_client_permission_groups WHERE client_id = 'aaeasy_mcp_resource_server';
UPDATE OR IGNORE oauth_metadata_client_approvals SET client_id = 'aaeasy_mcp_introspector'
WHERE client_id = 'aaeasy_mcp_resource_server';
UPDATE OR IGNORE oauth_client_assertion_jtis SET client_id = 'aaeasy_mcp_introspector'
WHERE client_id = 'aaeasy_mcp_resource_server';
DELETE FROM oauth_clients WHERE client_id = 'aaeasy_mcp_resource_server';

INSERT INTO groups (id, name, description, priority, created_at)
SELECT 'grp_aaeasy_users', 'aaeasy-users', 'Users entitled to AAEasy MCP', 100, unixepoch()
WHERE NOT EXISTS (SELECT 1 FROM groups WHERE name = 'aaeasy-users');

DELETE FROM permission_group_rules WHERE id IN (
  'prule_aaeasy_local_base',
  'prule_aaeasy_local_read',
  'prule_aaeasy_local_execute'
);
WITH target AS (
  SELECT id FROM groups WHERE name = 'aaeasy-users'
), next_position AS (
  SELECT COALESCE(MAX(position) + 1, 0) AS value
  FROM permission_group_rules
  WHERE group_id = (SELECT id FROM target)
)
INSERT INTO permission_group_rules
  (id, group_id, effect, condition_json, position, created_at, updated_at)
SELECT 'prule_aaeasy_local_base', target.id, 'allow',
       '{"field":"api","operator":"equals","value":"http://localhost:5173/mcp"}',
       next_position.value, unixepoch(), unixepoch()
FROM target, next_position
UNION ALL
SELECT 'prule_aaeasy_local_read', target.id, 'allow',
       '{"operator":"and","conditions":[{"field":"api","operator":"equals","value":"http://localhost:5173/mcp"},{"field":"scope","operator":"equals","value":"mcp.tools.read"}]}',
       next_position.value + 1, unixepoch(), unixepoch()
FROM target, next_position
UNION ALL
SELECT 'prule_aaeasy_local_execute', target.id, 'allow',
       '{"operator":"and","conditions":[{"field":"api","operator":"equals","value":"http://localhost:5173/mcp"},{"field":"scope","operator":"equals","value":"mcp.tools.execute"}]}',
       next_position.value + 2, unixepoch(), unixepoch()
FROM target, next_position;
