-- 0004_consent_resource_scope_policy.sql
-- Bind remembered consent to a specific resource and make resource scope
-- policy explicit for the OIDC grants already supported by the seeded clients.

CREATE TABLE consents_v2 (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,
  resource   TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (user_id, client_id, resource)
);

INSERT INTO consents_v2 (id, user_id, client_id, scope, resource, created_at, updated_at)
SELECT id, user_id, client_id, scope, COALESCE(resource, ''), created_at, updated_at
FROM consents;

DROP TABLE consents;
ALTER TABLE consents_v2 RENAME TO consents;
CREATE INDEX idx_consents_user ON consents (user_id);

UPDATE oauth_resources
SET allowed_scopes_json = json_insert(allowed_scopes_json, '$[#]', 'openid'),
    updated_at = unixepoch()
WHERE resource_uri IN (
    'https://api.pangda.app',
    'https://admin.pangda.app',
    'https://app.pangda.app',
    'urn:pangda:cloudflare-one'
  )
  AND NOT EXISTS (
    SELECT 1 FROM json_each(oauth_resources.allowed_scopes_json) WHERE value = 'openid'
  );

UPDATE oauth_resources
SET allowed_scopes_json = json_insert(allowed_scopes_json, '$[#]', 'profile'),
    updated_at = unixepoch()
WHERE resource_uri IN (
    'https://api.pangda.app',
    'https://admin.pangda.app',
    'https://app.pangda.app',
    'urn:pangda:cloudflare-one'
  )
  AND NOT EXISTS (
    SELECT 1 FROM json_each(oauth_resources.allowed_scopes_json) WHERE value = 'profile'
  );

UPDATE oauth_resources
SET allowed_scopes_json = json_insert(allowed_scopes_json, '$[#]', 'email'),
    updated_at = unixepoch()
WHERE resource_uri IN (
    'https://api.pangda.app',
    'https://admin.pangda.app',
    'https://app.pangda.app',
    'urn:pangda:cloudflare-one'
  )
  AND NOT EXISTS (
    SELECT 1 FROM json_each(oauth_resources.allowed_scopes_json) WHERE value = 'email'
  );

UPDATE oauth_resources
SET allowed_scopes_json = json_insert(allowed_scopes_json, '$[#]', 'groups'),
    updated_at = unixepoch()
WHERE resource_uri IN (
    'https://api.pangda.app',
    'https://admin.pangda.app',
    'https://app.pangda.app',
    'urn:pangda:cloudflare-one'
  )
  AND NOT EXISTS (
    SELECT 1 FROM json_each(oauth_resources.allowed_scopes_json) WHERE value = 'groups'
  );

UPDATE oauth_resources
SET allowed_scopes_json = json_insert(allowed_scopes_json, '$[#]', 'offline_access'),
    updated_at = unixepoch()
WHERE resource_uri IN (
    'https://api.pangda.app',
    'https://admin.pangda.app',
    'https://app.pangda.app'
  )
  AND NOT EXISTS (
    SELECT 1 FROM json_each(oauth_resources.allowed_scopes_json) WHERE value = 'offline_access'
  );

UPDATE oauth_clients
SET allowed_scopes_json = json_insert(allowed_scopes_json, '$[#]', 'groups'),
    updated_at = unixepoch()
WHERE client_id IN ('pangda_app', 'pangda_admin', 'cloudflare_one', 'pangda_cli')
  AND NOT EXISTS (
    SELECT 1 FROM json_each(oauth_clients.allowed_scopes_json) WHERE value = 'groups'
  );
