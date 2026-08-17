-- Permission groups are ordered policy containers. Rules are evaluated against
-- the current application/API/scope request; no matching allow is fail-closed.

ALTER TABLE groups
ADD COLUMN priority INTEGER NOT NULL DEFAULT 0
  CHECK (priority BETWEEN 0 AND 1000000);

CREATE TABLE permission_group_rules (
  id             TEXT PRIMARY KEY,
  group_id       TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  effect         TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
  condition_json TEXT NOT NULL CHECK (json_valid(condition_json)),
  position       INTEGER NOT NULL CHECK (position >= 0),
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  UNIQUE (group_id, position)
);

CREATE INDEX idx_permission_group_rules_group
  ON permission_group_rules (group_id, position, id);

-- Standard OIDC identity/session scopes are derived from base application/API
-- access and must never be independently configurable, including through a
-- direct database write that bypasses the application validator.
CREATE TRIGGER reject_standard_scope_rule_insert
BEFORE INSERT ON permission_group_rules
WHEN EXISTS (
  SELECT 1
  FROM json_tree(NEW.condition_json) AS condition_node
  WHERE condition_node.type = 'object'
    AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'scope'
    AND (
      CAST(json_extract(condition_node.value, '$.value') AS TEXT)
        IN ('openid', 'profile', 'email', 'offline_access')
      OR EXISTS (
        SELECT 1
        FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
        WHERE CAST(set_value.value AS TEXT)
          IN ('openid', 'profile', 'email', 'offline_access')
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'standard scope is authorized by application and API access');
END;

CREATE TRIGGER reject_standard_scope_rule_update
BEFORE UPDATE OF condition_json ON permission_group_rules
WHEN EXISTS (
  SELECT 1
  FROM json_tree(NEW.condition_json) AS condition_node
  WHERE condition_node.type = 'object'
    AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'scope'
    AND (
      CAST(json_extract(condition_node.value, '$.value') AS TEXT)
        IN ('openid', 'profile', 'email', 'offline_access')
      OR EXISTS (
        SELECT 1
        FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
        WHERE CAST(set_value.value AS TEXT)
          IN ('openid', 'profile', 'email', 'offline_access')
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'standard scope is authorized by application and API access');
END;

-- Removing a referenced catalog target deletes the whole rule rather than a
-- leaf. Removing only one leaf from an AND/OR tree could broaden the rule.
CREATE TRIGGER prune_permission_rules_after_client_delete
AFTER DELETE ON oauth_clients
BEGIN
  DELETE FROM permission_group_rules
  WHERE EXISTS (
    SELECT 1
    FROM json_tree(permission_group_rules.condition_json) AS condition_node
    WHERE condition_node.type = 'object'
      AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'application'
      AND (
        CAST(json_extract(condition_node.value, '$.value') AS TEXT) = OLD.client_id
        OR EXISTS (
          SELECT 1
          FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
          WHERE CAST(set_value.value AS TEXT) = OLD.client_id
        )
      )
  );
END;

CREATE TRIGGER prune_permission_rules_after_resource_delete
AFTER DELETE ON oauth_resources
BEGIN
  DELETE FROM permission_group_rules
  WHERE EXISTS (
    SELECT 1
    FROM json_tree(permission_group_rules.condition_json) AS condition_node
    WHERE condition_node.type = 'object'
      AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'api'
      AND (
        CAST(json_extract(condition_node.value, '$.value') AS TEXT) = OLD.resource_uri
        OR EXISTS (
          SELECT 1
          FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
          WHERE CAST(set_value.value AS TEXT) = OLD.resource_uri
        )
      )
  );
END;

-- Retiring a custom scope must also retire rules that could silently become
-- active again if the same scope is re-added later. Delete the complete rule:
-- pruning one branch from an AND/OR condition can accidentally broaden it.
CREATE TRIGGER prune_permission_rules_after_resource_scope_update
AFTER UPDATE OF allowed_scopes_json ON oauth_resources
BEGIN
  DELETE FROM permission_group_rules
  WHERE (
    EXISTS (
      SELECT 1
      FROM json_tree(permission_group_rules.condition_json) AS condition_node
      WHERE condition_node.type = 'object'
        AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'api'
        AND (
          CAST(json_extract(condition_node.value, '$.value') AS TEXT) = NEW.resource_uri
          OR EXISTS (
            SELECT 1
            FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
            WHERE CAST(set_value.value AS TEXT) = NEW.resource_uri
          )
        )
    )
    AND EXISTS (
      SELECT 1
      FROM json_tree(permission_group_rules.condition_json) AS condition_node
      WHERE condition_node.type = 'object'
        AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'scope'
        AND (
          (
            json_extract(condition_node.value, '$.value') IS NOT NULL
            AND CAST(json_extract(condition_node.value, '$.value') AS TEXT) NOT IN (
              SELECT CAST(value AS TEXT) FROM json_each(NEW.allowed_scopes_json)
            )
          )
          OR EXISTS (
            SELECT 1
            FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
            WHERE CAST(set_value.value AS TEXT) NOT IN (
              SELECT CAST(value AS TEXT) FROM json_each(NEW.allowed_scopes_json)
            )
          )
        )
    )
  )
  OR EXISTS (
    SELECT 1
    FROM json_tree(permission_group_rules.condition_json) AS condition_node
    WHERE condition_node.type = 'object'
      AND CAST(json_extract(condition_node.value, '$.field') AS TEXT) = 'scope'
      AND (
        (
          json_extract(condition_node.value, '$.value') IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM oauth_resources AS resource
            JOIN json_each(resource.allowed_scopes_json) AS offered_scope
            WHERE CAST(offered_scope.value AS TEXT) =
              CAST(json_extract(condition_node.value, '$.value') AS TEXT)
          )
        )
        OR EXISTS (
          SELECT 1
          FROM json_each(COALESCE(json_extract(condition_node.value, '$.values'), '[]')) AS set_value
          WHERE NOT EXISTS (
            SELECT 1
            FROM oauth_resources AS resource
            JOIN json_each(resource.allowed_scopes_json) AS offered_scope
            WHERE CAST(offered_scope.value AS TEXT) = CAST(set_value.value AS TEXT)
          )
        )
      )
  );
END;

-- Translate each legacy group that independently targeted at least one client
-- and one API into one base allow rule. Requiring both targets in the same
-- membership is deliberately fail-closed for legacy cross-group composition.
INSERT INTO permission_group_rules
  (id, group_id, effect, condition_json, position, created_at, updated_at)
SELECT
  'prule_migrated_base_' || permission_group.id,
  permission_group.id,
  'allow',
  json_object(
    'operator', 'and',
    'conditions', json_array(
      json_object(
        'operator', 'or',
        'conditions', json((
          SELECT json_group_array(
            json_object(
              'field', 'application',
              'operator', 'equals',
              'value', client_access.client_id
            )
          )
          FROM oauth_client_permission_groups AS client_access
          WHERE client_access.group_id = permission_group.id
          ORDER BY client_access.client_id
        ))
      ),
      json_object(
        'operator', 'or',
        'conditions', json((
          SELECT json_group_array(
            json_object(
              'field', 'api',
              'operator', 'equals',
              'value', resource_access.resource_uri
            )
          )
          FROM oauth_resource_permission_groups AS resource_access
          WHERE resource_access.group_id = permission_group.id
          ORDER BY resource_access.resource_uri
        ))
      )
    )
  ),
  0,
  unixepoch(),
  unixepoch()
FROM groups AS permission_group
WHERE EXISTS (
  SELECT 1 FROM oauth_client_permission_groups
  WHERE group_id = permission_group.id
)
AND EXISTS (
  SELECT 1 FROM oauth_resource_permission_groups
  WHERE group_id = permission_group.id
);

-- The built-in administrator path historically composes the universally
-- available admin application with the admins-only API. Preserve that secure
-- split explicitly under the protected admins group.
INSERT INTO permission_group_rules
  (id, group_id, effect, condition_json, position, created_at, updated_at)
SELECT
  'prule_migrated_admin_base',
  admin_group.id,
  'allow',
  json_object(
    'operator', 'and',
    'conditions', json_array(
      json_object('field', 'application', 'operator', 'equals', 'value', 'pangda_admin'),
      json_object('field', 'api', 'operator', 'equals', 'value', 'https://admin.pangda.app')
    )
  ),
  COALESCE((SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = admin_group.id), 0),
  unixepoch(),
  unixepoch()
FROM groups AS admin_group
WHERE admin_group.name = 'admins'
  AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = 'pangda_admin')
  AND EXISTS (
    SELECT 1 FROM oauth_resources WHERE resource_uri = 'https://admin.pangda.app'
  )
  AND NOT EXISTS (
    SELECT 1 FROM permission_group_rules
    WHERE group_id = admin_group.id AND id = 'prule_migrated_admin_base'
  );

-- Legacy target access implicitly allowed every offered custom scope unless
-- that resource/scope had an explicit allow policy. Materialize those grants
-- so the new engine can make unconfigured custom scopes default-deny.
INSERT INTO permission_group_rules
  (id, group_id, effect, condition_json, position, created_at, updated_at)
SELECT
  'prule_' || lower(hex(randomblob(16))),
  resource_access.group_id,
  'allow',
  json_object(
    'operator', 'and',
    'conditions', json_array(
      json_object(
        'field', 'api', 'operator', 'equals', 'value', resource_access.resource_uri
      ),
      json_object(
        'field', 'scope', 'operator', 'equals', 'value', offered_scope.value
      )
    )
  ),
  ROW_NUMBER() OVER (
    PARTITION BY resource_access.group_id
    ORDER BY resource_access.resource_uri, CAST(offered_scope.value AS TEXT)
  ) + COALESCE((
    SELECT MAX(existing.position)
    FROM permission_group_rules AS existing
    WHERE existing.group_id = resource_access.group_id
  ), -1),
  unixepoch(),
  unixepoch()
FROM oauth_resource_permission_groups AS resource_access
JOIN oauth_resources AS resource
  ON resource.resource_uri = resource_access.resource_uri
JOIN json_each(resource.allowed_scopes_json) AS offered_scope
WHERE CAST(offered_scope.value AS TEXT)
      NOT IN ('openid', 'profile', 'email', 'offline_access')
  AND NOT EXISTS (
    SELECT 1
    FROM oauth_scope_permission_groups AS explicit_allow
    WHERE explicit_allow.resource_uri = resource_access.resource_uri
      AND explicit_allow.scope = CAST(offered_scope.value AS TEXT)
      AND explicit_allow.effect = 'allow'
  );

-- Preserve explicit legacy allow/deny refinements. At the default equal
-- priority, deny continues to win ties.
INSERT INTO permission_group_rules
  (id, group_id, effect, condition_json, position, created_at, updated_at)
SELECT
  'prule_' || lower(hex(randomblob(16))),
  scope_policy.group_id,
  scope_policy.effect,
  json_object(
    'operator', 'and',
    'conditions', json_array(
      json_object(
        'field', 'api', 'operator', 'equals', 'value', scope_policy.resource_uri
      ),
      json_object(
        'field', 'scope', 'operator', 'equals', 'value', scope_policy.scope
      )
    )
  ),
  ROW_NUMBER() OVER (
    PARTITION BY scope_policy.group_id
    ORDER BY scope_policy.resource_uri, scope_policy.scope, scope_policy.effect
  ) + COALESCE((
    SELECT MAX(existing.position)
    FROM permission_group_rules AS existing
    WHERE existing.group_id = scope_policy.group_id
  ), -1),
  scope_policy.created_at,
  unixepoch()
FROM oauth_scope_permission_groups AS scope_policy
WHERE scope_policy.scope NOT IN ('openid', 'profile', 'email', 'offline_access');

-- Keep the legacy table fail-closed for older tooling during the transition.
DELETE FROM oauth_scope_permission_groups WHERE scope = 'email';

DROP TRIGGER reject_resource_authorized_scope_permission_insert;
DROP TRIGGER reject_resource_authorized_scope_permission_update;

CREATE TRIGGER reject_resource_authorized_scope_permission_insert
BEFORE INSERT ON oauth_scope_permission_groups
WHEN NEW.scope IN ('openid', 'profile', 'email', 'offline_access')
BEGIN
  SELECT RAISE(ABORT, 'scope is authorized directly by resource access');
END;

CREATE TRIGGER reject_resource_authorized_scope_permission_update
BEFORE UPDATE OF scope ON oauth_scope_permission_groups
WHEN NEW.scope IN ('openid', 'profile', 'email', 'offline_access')
BEGIN
  SELECT RAISE(ABORT, 'scope is authorized directly by resource access');
END;
