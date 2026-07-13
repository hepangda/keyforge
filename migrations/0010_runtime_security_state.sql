-- Strongly-consistent runtime state used by security-sensitive continuations
-- and signing-key rotation, plus the browser session that approved a device.

CREATE TABLE reauth_continuations (
  token_hash   TEXT PRIMARY KEY,
  session_id   TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
  request_hash TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);
CREATE INDEX idx_reauth_continuations_expiry ON reauth_continuations (expires_at);

CREATE TABLE signing_key_state (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  keyring_json TEXT NOT NULL,
  version      INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

CREATE TABLE maintenance_state (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Every password/email/status security transition increments this epoch.
-- One-time login and recovery capabilities are bound to the epoch at issue.
ALTER TABLE users ADD COLUMN security_version INTEGER NOT NULL DEFAULT 0;

ALTER TABLE device_authorization_sessions ADD COLUMN session_id TEXT REFERENCES sessions (id) ON DELETE SET NULL;
ALTER TABLE device_authorization_sessions ADD COLUMN auth_time INTEGER;

-- Invariants and hot-path indexes used by revocation and bounded cleanup.
CREATE UNIQUE INDEX idx_users_email_canonical ON users (lower(email));
CREATE UNIQUE INDEX idx_groups_name_canonical ON groups (lower(name));
CREATE INDEX idx_refresh_session_revoked ON refresh_tokens (session_id, revoked_at);
CREATE INDEX idx_refresh_terminal ON refresh_tokens (expires_at, revoked_at);
CREATE INDEX idx_sessions_terminal ON sessions (expires_at, revoked_at);
CREATE INDEX idx_password_reset_terminal ON password_reset_tokens (expires_at, consumed_at);
CREATE INDEX idx_email_verification_terminal ON email_verifications (expires_at, consumed_at);
CREATE INDEX idx_grants_created ON authorization_grants (created_at);
CREATE INDEX idx_device_terminal ON device_authorization_sessions (expires_at, status, created_at);
CREATE INDEX idx_audit_created_id ON audit_logs (created_at, id);
