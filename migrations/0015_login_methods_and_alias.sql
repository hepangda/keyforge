-- Unify local login methods, add a stable username, and retire legacy account
-- classification / social identities.

-- Existing accounts receive a deterministic, unique alias derived from their
-- user id. Administrators and users can replace it with a friendlier value.
ALTER TABLE users ADD COLUMN alias TEXT NOT NULL DEFAULT 'user'
  CHECK (
    length(alias) BETWEEN 1 AND 64
    AND alias NOT GLOB '*[^A-Za-z0-9]*'
  );

UPDATE users
SET alias = 'user' || lower(replace(id, '_', ''));

CREATE UNIQUE INDEX idx_users_alias_canonical ON users (lower(alias));

-- Every account is internal. Remove the classification instead of retaining
-- a second source of truth that callers could accidentally authorize against.
ALTER TABLE users DROP COLUMN user_type;

-- Passwords are login methods with their own ids and labels, just like
-- passkeys. Migrated passwords predate the six-character policy and were
-- created under the former 12-character minimum, so they are safe for admins.
CREATE TABLE password_credentials_v2 (
  id               TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  password_hash    TEXT NOT NULL,
  name             TEXT,
  admin_eligible   INTEGER NOT NULL DEFAULT 1 CHECK (admin_eligible IN (0, 1)),
  created_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL,
  last_used_at     INTEGER
);

INSERT INTO password_credentials_v2 (
  id, user_id, password_hash, name, admin_eligible, created_at, updated_at
)
SELECT
  'pwd_' || lower(hex(randomblob(16))),
  user_id,
  password_hash,
  'Password',
  1,
  updated_at,
  updated_at
FROM password_credentials;

DROP TABLE password_credentials;
ALTER TABLE password_credentials_v2 RENAME TO password_credentials;
CREATE INDEX idx_password_credentials_user ON password_credentials (user_id, created_at);

-- Social login is no longer a supported entry point. Revoke sessions created
-- through those providers and their refresh-token mirrors before removing the
-- provider identity catalog.
UPDATE refresh_tokens
SET revoked_at = unixepoch()
WHERE revoked_at IS NULL
  AND session_id IN (
    SELECT id FROM sessions WHERE auth_method IN ('github', 'google')
  );

UPDATE sessions
SET revoked_at = unixepoch()
WHERE revoked_at IS NULL AND auth_method IN ('github', 'google');

DROP TABLE identities;
