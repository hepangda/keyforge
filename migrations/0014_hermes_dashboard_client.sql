-- Register Hermes Dashboard as a public OIDC relying party.
--
-- Hermes v2026.6.19 authenticates self-hosted OIDC clients with
-- authorization code + S256 PKCE and does not send a client secret. Keep this
-- client public and give it a dedicated resource rather than reusing one of
-- the Pangda application/API audiences.

INSERT INTO oauth_resources (
  resource_uri, name, allowed_scopes_json, enabled, created_at, updated_at
) VALUES (
  'urn:pangda:hermes-agent',
  'Hermes Agent',
  '["openid","profile","email","groups","offline_access"]',
  1,
  unixepoch(),
  unixepoch()
)
ON CONFLICT(resource_uri) DO UPDATE SET
  name = excluded.name,
  allowed_scopes_json = excluded.allowed_scopes_json,
  enabled = 1,
  updated_at = unixepoch();

INSERT INTO oauth_clients (
  client_id,
  client_secret_hash,
  type,
  client_kind,
  name,
  redirect_uris_json,
  post_logout_redirect_uris_json,
  allowed_scopes_json,
  allowed_grant_types_json,
  allowed_resources_json,
  default_resource,
  require_pkce,
  enabled,
  created_at,
  updated_at
) VALUES (
  'hermes_dashboard',
  NULL,
  'public',
  'application',
  'Hermes Dashboard',
  '["https://hermes.pdbb.net/auth/callback"]',
  '["https://hermes.pdbb.net/"]',
  '["openid","profile","email","offline_access"]',
  '["authorization_code","refresh_token"]',
  '["urn:pangda:hermes-agent"]',
  'urn:pangda:hermes-agent',
  1,
  1,
  unixepoch(),
  unixepoch()
)
ON CONFLICT(client_id) DO UPDATE SET
  client_secret_hash = NULL,
  type = 'public',
  client_kind = 'application',
  name = excluded.name,
  redirect_uris_json = excluded.redirect_uris_json,
  post_logout_redirect_uris_json = excluded.post_logout_redirect_uris_json,
  allowed_scopes_json = excluded.allowed_scopes_json,
  allowed_grant_types_json = excluded.allowed_grant_types_json,
  allowed_resources_json = excluded.allowed_resources_json,
  default_resource = excluded.default_resource,
  require_pkce = 1,
  enabled = 1,
  updated_at = unixepoch();
