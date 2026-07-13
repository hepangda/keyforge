-- Index each bounded maintenance branch independently.  The previous
-- expires_at-first composites could not service revoked/consumed/status
-- branches and forced hourly scans when few rows were eligible.

DROP INDEX IF EXISTS idx_sessions_expires;
DROP INDEX IF EXISTS idx_sessions_terminal;
CREATE INDEX idx_sessions_cleanup_expires ON sessions (expires_at, id);
CREATE INDEX idx_sessions_cleanup_revoked
  ON sessions (revoked_at, id) WHERE revoked_at IS NOT NULL;

DROP INDEX IF EXISTS idx_refresh_terminal;
CREATE INDEX idx_refresh_cleanup_expires ON refresh_tokens (expires_at, id);
CREATE INDEX idx_refresh_cleanup_revoked
  ON refresh_tokens (revoked_at, id) WHERE revoked_at IS NOT NULL;

DROP INDEX IF EXISTS idx_password_reset_terminal;
CREATE INDEX idx_password_reset_cleanup_expires ON password_reset_tokens (expires_at, id);
CREATE INDEX idx_password_reset_cleanup_consumed
  ON password_reset_tokens (consumed_at, id) WHERE consumed_at IS NOT NULL;

DROP INDEX IF EXISTS idx_email_verification_terminal;
CREATE INDEX idx_email_verification_cleanup_expires ON email_verifications (expires_at, id);
CREATE INDEX idx_email_verification_cleanup_consumed
  ON email_verifications (consumed_at, id) WHERE consumed_at IS NOT NULL;

DROP INDEX IF EXISTS idx_grants_created;
CREATE INDEX idx_grants_cleanup_created ON authorization_grants (created_at, id);

DROP INDEX IF EXISTS idx_device_status;
DROP INDEX IF EXISTS idx_device_expires;
DROP INDEX IF EXISTS idx_device_terminal;
CREATE INDEX idx_device_cleanup_expires ON device_authorization_sessions (expires_at, id);
CREATE INDEX idx_device_cleanup_status_created
  ON device_authorization_sessions (status, created_at, id);
CREATE INDEX idx_device_client_active
  ON device_authorization_sessions (client_id, status, expires_at);

DROP INDEX IF EXISTS idx_reauth_continuations_expiry;
CREATE INDEX idx_reauth_cleanup_expires ON reauth_continuations (expires_at, token_hash);
CREATE INDEX idx_reauth_cleanup_consumed
  ON reauth_continuations (consumed_at, token_hash) WHERE consumed_at IS NOT NULL;
