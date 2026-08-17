-- Identity and session scopes follow the application/resource assignment.
-- They cannot be narrowed by permission-group scope rules.

DELETE FROM oauth_scope_permission_groups
WHERE scope IN ('openid', 'profile', 'offline_access');

CREATE TRIGGER reject_resource_authorized_scope_permission_insert
BEFORE INSERT ON oauth_scope_permission_groups
WHEN NEW.scope IN ('openid', 'profile', 'offline_access')
BEGIN
  SELECT RAISE(ABORT, 'scope is authorized directly by resource access');
END;

CREATE TRIGGER reject_resource_authorized_scope_permission_update
BEFORE UPDATE OF scope ON oauth_scope_permission_groups
WHEN NEW.scope IN ('openid', 'profile', 'offline_access')
BEGIN
  SELECT RAISE(ABORT, 'scope is authorized directly by resource access');
END;
