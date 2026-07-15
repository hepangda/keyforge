-- Local demo-only account. This file is applied explicitly by selftest.mjs and
-- is never part of the production migration chain.
INSERT OR REPLACE INTO users
  (id, email, alias, email_verified, name, disabled, created_at, updated_at)
VALUES
  ('usr_demo_admin', 'demo-admin', 'demoadmin', 1, 'Demo Administrator', 0, unixepoch(), unixepoch());

INSERT OR REPLACE INTO password_credentials
  (id, user_id, password_hash, name, admin_eligible, created_at, updated_at)
VALUES (
  'pwd_demo_admin',
  'usr_demo_admin',
  'scrypt$32768$8$1$ABEiM0RVZneImaq7zN3u_w$XIk-GTbU6FjhZSxeVcPlN5XkbHveUOZf8zLj-1Y4hVI',
  'Demo password',
  1,
  unixepoch(),
  unixepoch()
);

INSERT OR REPLACE INTO user_groups (user_id, group_id, created_at)
VALUES ('usr_demo_admin', 'grp_seed_admins', unixepoch());
