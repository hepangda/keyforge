-- Allow hyphens and underscores in administrator-managed sign-in names while
-- preserving existing aliases and their case-insensitive uniqueness.

DROP INDEX idx_users_alias_canonical;

ALTER TABLE users RENAME COLUMN alias TO alias_legacy;

ALTER TABLE users ADD COLUMN alias TEXT NOT NULL DEFAULT 'user'
  CHECK (
    length(alias) BETWEEN 1 AND 64
    AND alias NOT GLOB '*[^A-Za-z0-9_-]*'
  );

UPDATE users SET alias = alias_legacy;

ALTER TABLE users DROP COLUMN alias_legacy;

CREATE UNIQUE INDEX idx_users_alias_canonical ON users (lower(alias));
