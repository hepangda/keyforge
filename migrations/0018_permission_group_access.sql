-- Fail-closed permission-group authorization for user-backed OAuth clients and
-- resources. Assignments reference stable group IDs and disappear with either
-- target or group deletion.

CREATE TABLE oauth_client_permission_groups (
  client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  group_id   TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, group_id)
);
CREATE INDEX idx_oauth_client_permission_groups_group
  ON oauth_client_permission_groups (group_id, client_id);

CREATE TABLE oauth_resource_permission_groups (
  resource_uri TEXT NOT NULL REFERENCES oauth_resources (resource_uri) ON DELETE CASCADE,
  group_id     TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (resource_uri, group_id)
);
CREATE INDEX idx_oauth_resource_permission_groups_group
  ON oauth_resource_permission_groups (group_id, resource_uri);

-- Preserve scope order while retiring the OIDC `groups` scope everywhere.
UPDATE oauth_clients
SET allowed_scopes_json = (
  SELECT json_group_array(value)
  FROM (
    SELECT value
    FROM json_each(oauth_clients.allowed_scopes_json)
    WHERE value <> 'groups'
    ORDER BY CAST(key AS INTEGER)
  )
);

UPDATE oauth_resources
SET allowed_scopes_json = (
  SELECT json_group_array(value)
  FROM (
    SELECT value
    FROM json_each(oauth_resources.allowed_scopes_json)
    WHERE value <> 'groups'
    ORDER BY CAST(key AS INTEGER)
  )
);

UPDATE consents
SET scope = trim(replace(' ' || scope || ' ', ' groups ', ' '))
WHERE scope = 'groups'
   OR scope LIKE 'groups %'
   OR scope LIKE '% groups'
   OR scope LIKE '% groups %';
DELETE FROM consents WHERE scope = '';

UPDATE refresh_tokens
SET scope = trim(replace(' ' || scope || ' ', ' groups ', ' ')),
    revoked_at = CASE
      WHEN trim(replace(' ' || scope || ' ', ' groups ', ' ')) = '' THEN unixepoch()
      ELSE revoked_at
    END
WHERE scope = 'groups'
   OR scope LIKE 'groups %'
   OR scope LIKE '% groups'
   OR scope LIKE '% groups %';

UPDATE authorization_grants
SET scope = trim(replace(' ' || scope || ' ', ' groups ', ' '))
WHERE scope = 'groups'
   OR scope LIKE 'groups %'
   OR scope LIKE '% groups'
   OR scope LIKE '% groups %';

UPDATE device_authorization_sessions
SET scope = trim(replace(' ' || scope || ' ', ' groups ', ' ')),
    status = CASE
      WHEN trim(replace(' ' || scope || ' ', ' groups ', ' ')) = ''
        AND status IN ('pending', 'approved') THEN 'denied'
      ELSE status
    END,
    denied_at = CASE
      WHEN trim(replace(' ' || scope || ' ', ' groups ', ' ')) = ''
        AND status IN ('pending', 'approved') THEN unixepoch()
      ELSE denied_at
    END
WHERE scope = 'groups'
   OR scope LIKE 'groups %'
   OR scope LIKE '% groups'
   OR scope LIKE '% groups %';

-- Seed only targets that still exist. Operators may have removed any of these
-- optional catalog rows before this migration runs.
INSERT INTO oauth_client_permission_groups (client_id, group_id, created_at)
SELECT client.client_id, permission_group.id, unixepoch()
FROM oauth_clients AS client
JOIN groups AS permission_group ON permission_group.id = 'grp_seed_employees'
WHERE client.client_id IN ('pangda_app', 'cloudflare_one', 'pangda_cli', 'hermes_dashboard');

INSERT INTO oauth_resource_permission_groups (resource_uri, group_id, created_at)
SELECT resource.resource_uri, permission_group.id, unixepoch()
FROM oauth_resources AS resource
JOIN groups AS permission_group ON permission_group.id = 'grp_seed_employees'
WHERE resource.resource_uri IN (
  'https://api.pangda.app',
  'https://app.pangda.app',
  'urn:pangda:cloudflare-one',
  'urn:pangda:hermes-agent'
);

INSERT INTO oauth_client_permission_groups (client_id, group_id, created_at)
SELECT client.client_id, permission_group.id, unixepoch()
FROM oauth_clients AS client
JOIN groups AS permission_group ON permission_group.id = 'grp_seed_admins'
WHERE client.client_id = 'pangda_admin';

INSERT INTO oauth_resource_permission_groups (resource_uri, group_id, created_at)
SELECT resource.resource_uri, permission_group.id, unixepoch()
FROM oauth_resources AS resource
JOIN groups AS permission_group ON permission_group.id = 'grp_seed_admins'
WHERE resource.resource_uri = 'https://admin.pangda.app';
