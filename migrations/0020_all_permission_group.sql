-- Built-in universal membership. Existing users are backfilled and every new
-- user is joined automatically, regardless of which account-creation path is
-- used.

-- `all` was previously a valid custom name. Preserve any such group's members
-- and assignments under a deterministic legacy name rather than broadening its
-- access when universal membership is backfilled.
UPDATE groups
SET name = 'legacy-all-' || substr(lower(hex(id)), 1, 40)
WHERE name = 'all'
  AND id != 'grp_seed_all';

INSERT INTO groups (id, name, description, created_at)
VALUES ('grp_seed_all', 'all', 'All users', unixepoch());

INSERT OR IGNORE INTO user_groups (user_id, group_id, created_at)
SELECT users.id, universal_group.id, unixepoch()
FROM users
JOIN groups AS universal_group ON universal_group.name = 'all';

CREATE TRIGGER add_all_group_membership_after_user_insert
AFTER INSERT ON users
BEGIN
  INSERT OR IGNORE INTO user_groups (user_id, group_id, created_at)
  SELECT NEW.id, groups.id, NEW.created_at
  FROM groups
  WHERE groups.name = 'all';
END;

-- The admin application is available to every account; membership in admins
-- independently gates the Admin API resource.
DELETE FROM oauth_client_permission_groups
WHERE client_id = 'pangda_admin'
  AND group_id IN (SELECT id FROM groups WHERE name = 'admins');

INSERT OR IGNORE INTO oauth_client_permission_groups (client_id, group_id, created_at)
SELECT clients.client_id, universal_group.id, unixepoch()
FROM oauth_clients AS clients
JOIN groups AS universal_group ON universal_group.name = 'all'
WHERE clients.client_id = 'pangda_admin';
