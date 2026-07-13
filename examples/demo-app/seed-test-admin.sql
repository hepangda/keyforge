-- Local demo-only identity. This file is applied explicitly by selftest.mjs and
-- is never part of the production migration chain.
INSERT OR REPLACE INTO users
  (id, email, email_verified, name, user_type, disabled, created_at, updated_at)
VALUES
  ('usr_demo_admin', 'demo-admin', 1, 'Demo Administrator', 'internal', 0, unixepoch(), unixepoch());

INSERT OR REPLACE INTO password_credentials (user_id, password_hash, updated_at)
VALUES (
  'usr_demo_admin',
  'scrypt$32768$8$1$yVLhH6oa6f3is1oUx0mLCg$iev7MtM5HU75bcTn8fv3AVGHeTZQg4sx-AlPLAWHJMA',
  unixepoch()
);

INSERT OR REPLACE INTO user_groups (user_id, group_id, created_at)
VALUES ('usr_demo_admin', 'grp_seed_admins', unixepoch());
