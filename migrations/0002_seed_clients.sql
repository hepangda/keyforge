-- 0002_seed_clients.sql — initial OAuth clients, resources, and groups.
-- Confidential clients (cloudflare_one, svc_internal_worker) are seeded with a
-- NULL secret hash on purpose: secrets are never committed. Set each one via
-- `POST /admin/clients/:id/rotate-secret` (shown once) before first use.

-- ── groups ───────────────────────────────────────────────────────────────
INSERT INTO groups (id, name, description, created_at) VALUES
  ('grp_seed_employees', 'employees', 'Internal Pangda staff', unixepoch()),
  ('grp_seed_admins',    'admins',    'Administrators with elevated access', unixepoch());

-- ── resources (access-token audiences) ───────────────────────────────────
INSERT INTO oauth_resources (resource_uri, name, allowed_scopes_json, enabled, created_at, updated_at) VALUES
  ('https://api.pangda.app',    'Pangda API',       '["openid","profile","email","groups","offline_access","api.read","api.write"]',       1, unixepoch(), unixepoch()),
  ('https://admin.pangda.app',  'Pangda Admin API', '["openid","profile","email","groups","offline_access","admin.read","admin.write"]',   1, unixepoch(), unixepoch()),
  ('https://app.pangda.app',    'Pangda App',       '["openid","profile","email","groups","offline_access","app.read"]',                   1, unixepoch(), unixepoch()),
  ('urn:pangda:cloudflare-one', 'Cloudflare One',   '["openid","profile","email","groups"]',   1, unixepoch(), unixepoch());

-- ── clients ──────────────────────────────────────────────────────────────
INSERT INTO oauth_clients (
  client_id, client_secret_hash, type, client_kind, name,
  redirect_uris_json, allowed_scopes_json, allowed_grant_types_json,
  allowed_resources_json, default_resource, require_pkce, enabled,
  created_at, updated_at
) VALUES
  (
    'pangda_app', NULL, 'public', 'application', 'Pangda App',
    '["https://app.pangda.app/auth/callback"]',
    '["openid","profile","email","groups","offline_access","app.read","api.read","api.write"]',
    '["authorization_code","refresh_token"]',
    '["https://app.pangda.app","https://api.pangda.app"]',
    'https://api.pangda.app', 1, 1, unixepoch(), unixepoch()
  ),
  (
    'pangda_admin', NULL, 'public', 'application', 'Pangda Admin',
    '["https://admin.pangda.app/auth/callback"]',
    '["openid","profile","email","groups","offline_access","admin.read","admin.write"]',
    '["authorization_code","refresh_token"]',
    '["https://admin.pangda.app"]',
    'https://admin.pangda.app', 1, 1, unixepoch(), unixepoch()
  ),
  (
    'cloudflare_one', NULL, 'confidential', 'application', 'Cloudflare One',
    '["https://pangda.cloudflareaccess.com/cdn-cgi/access/callback"]',
    '["openid","profile","email","groups"]',
    '["authorization_code"]',
    '["urn:pangda:cloudflare-one"]',
    'urn:pangda:cloudflare-one', 1, 1, unixepoch(), unixepoch()
  ),
  (
    'pangda_cli', NULL, 'public', 'device', 'Pangda CLI',
    '[]',
    '["openid","profile","email","groups","offline_access","api.read","api.write"]',
    '["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]',
    '["https://api.pangda.app"]',
    'https://api.pangda.app', 1, 1, unixepoch(), unixepoch()
  ),
  (
    'svc_internal_worker', NULL, 'confidential', 'service', 'Internal Worker Service',
    '[]',
    '["api.read","api.write"]',
    '["client_credentials"]',
    '["https://api.pangda.app"]',
    'https://api.pangda.app', 1, 1, unixepoch(), unixepoch()
  );
