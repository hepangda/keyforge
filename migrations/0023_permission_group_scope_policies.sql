-- Resource-scoped permission-group policies. A deny held by any current
-- membership overrides allow; when at least one allow exists for a
-- resource/scope pair, users must hold one of those allowing groups.
-- Pairs with no rules preserve the existing target-level behaviour.

CREATE TABLE oauth_scope_permission_groups (
  resource_uri TEXT NOT NULL REFERENCES oauth_resources (resource_uri) ON DELETE CASCADE,
  scope        TEXT NOT NULL CHECK (scope <> ''),
  group_id     TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  effect       TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (resource_uri, scope, group_id)
);

CREATE INDEX idx_oauth_scope_permission_groups_group
  ON oauth_scope_permission_groups (group_id, resource_uri, scope);

CREATE TRIGGER validate_oauth_scope_permission_insert
BEFORE INSERT ON oauth_scope_permission_groups
WHEN NOT EXISTS (
  SELECT 1
  FROM oauth_resources AS resource
  JOIN json_each(resource.allowed_scopes_json) AS offered_scope
  WHERE resource.resource_uri = NEW.resource_uri
    AND CAST(offered_scope.value AS TEXT) = NEW.scope
)
BEGIN
  SELECT RAISE(ABORT, 'scope permission references an unavailable scope');
END;

CREATE TRIGGER validate_oauth_scope_permission_update
BEFORE UPDATE OF resource_uri, scope ON oauth_scope_permission_groups
WHEN NOT EXISTS (
  SELECT 1
  FROM oauth_resources AS resource
  JOIN json_each(resource.allowed_scopes_json) AS offered_scope
  WHERE resource.resource_uri = NEW.resource_uri
    AND CAST(offered_scope.value AS TEXT) = NEW.scope
)
BEGIN
  SELECT RAISE(ABORT, 'scope permission references an unavailable scope');
END;

CREATE TRIGGER prune_oauth_scope_permissions_after_resource_scope_update
AFTER UPDATE OF allowed_scopes_json ON oauth_resources
BEGIN
  DELETE FROM oauth_scope_permission_groups
  WHERE resource_uri = NEW.resource_uri
    AND scope NOT IN (
      SELECT CAST(value AS TEXT) FROM json_each(NEW.allowed_scopes_json)
    );
END;
