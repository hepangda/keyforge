-- 0001_initial.sql — KeyForge authorization server schema.
-- Conventions: TEXT ids (prefixed ULID), INTEGER UNIX-seconds timestamps,
-- INTEGER booleans (0/1), *_json columns hold JSON arrays/objects, and only
-- hashes of secrets/tokens are ever stored.

-- ── users ────────────────────────────────────────────────────────────────
CREATE TABLE users (
  id             TEXT PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  name           TEXT,
  picture        TEXT,
  user_type      TEXT NOT NULL DEFAULT 'external' CHECK (user_type IN ('internal', 'external')),
  disabled       INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
CREATE INDEX idx_users_email ON users (email);

-- ── groups ───────────────────────────────────────────────────────────────
CREATE TABLE groups (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE user_groups (
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  group_id   TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, group_id)
);
CREATE INDEX idx_user_groups_group ON user_groups (group_id);

-- ── identities (federated: github/google) ────────────────────────────────
CREATE TABLE identities (
  id               TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider         TEXT NOT NULL CHECK (provider IN ('github', 'google')),
  provider_user_id TEXT NOT NULL,
  email            TEXT,
  email_verified   INTEGER NOT NULL DEFAULT 0,
  profile_json     TEXT,
  created_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL,
  UNIQUE (provider, provider_user_id)
);
CREATE INDEX idx_identities_user ON identities (user_id);

-- ── credentials ──────────────────────────────────────────────────────────
CREATE TABLE password_credentials (
  user_id       TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE webauthn_credentials (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key    TEXT NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,
  transports    TEXT,
  aaguid        TEXT,
  name          TEXT,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);
CREATE INDEX idx_webauthn_user ON webauthn_credentials (user_id);

-- ── oauth clients / resources ────────────────────────────────────────────
CREATE TABLE oauth_clients (
  client_id                TEXT PRIMARY KEY,
  client_secret_hash       TEXT,
  type                     TEXT NOT NULL CHECK (type IN ('public', 'confidential')),
  client_kind              TEXT NOT NULL CHECK (client_kind IN ('application', 'device', 'service')),
  name                     TEXT NOT NULL,
  redirect_uris_json       TEXT NOT NULL DEFAULT '[]',
  allowed_scopes_json      TEXT NOT NULL DEFAULT '[]',
  allowed_grant_types_json TEXT NOT NULL DEFAULT '[]',
  allowed_resources_json   TEXT NOT NULL DEFAULT '[]',
  default_resource         TEXT,
  require_pkce             INTEGER NOT NULL DEFAULT 1,
  enabled                  INTEGER NOT NULL DEFAULT 1,
  created_at               INTEGER NOT NULL,
  updated_at               INTEGER NOT NULL
);

CREATE TABLE oauth_resources (
  resource_uri        TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  allowed_scopes_json TEXT NOT NULL DEFAULT '[]',
  enabled             INTEGER NOT NULL DEFAULT 1,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);

-- ── consents ─────────────────────────────────────────────────────────────
CREATE TABLE consents (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,
  resource   TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (user_id, client_id)
);
CREATE INDEX idx_consents_user ON consents (user_id);

-- ── sessions (server-side) ───────────────────────────────────────────────
CREATE TABLE sessions (
  id                    TEXT PRIMARY KEY,
  user_id               TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash            TEXT NOT NULL UNIQUE,
  auth_method           TEXT NOT NULL,
  auth_time             INTEGER NOT NULL,
  passkey_authenticated INTEGER NOT NULL DEFAULT 0,
  amr_json              TEXT,
  ip_hash               TEXT,
  user_agent_hash       TEXT,
  created_at            INTEGER NOT NULL,
  last_seen_at          INTEGER NOT NULL,
  expires_at            INTEGER NOT NULL,
  revoked_at            INTEGER
);
CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

-- ── refresh tokens (hash only; family mirror of RefreshTokenFamilyDO) ─────
CREATE TABLE refresh_tokens (
  id              TEXT PRIMARY KEY,
  token_hash      TEXT NOT NULL UNIQUE,
  user_id         TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id       TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  session_id      TEXT REFERENCES sessions (id) ON DELETE SET NULL,
  resource        TEXT NOT NULL,
  scope           TEXT NOT NULL,
  generation      INTEGER NOT NULL DEFAULT 0,
  remember_me     INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  last_rotated_at INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE INDEX idx_refresh_user ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_client ON refresh_tokens (client_id);

-- ── authorization grants (issued-grant history) ──────────────────────────
CREATE TABLE authorization_grants (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  session_id TEXT REFERENCES sessions (id) ON DELETE SET NULL,
  scope      TEXT NOT NULL,
  resource   TEXT NOT NULL,
  grant_type TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX idx_grants_user ON authorization_grants (user_id);
CREATE INDEX idx_grants_client ON authorization_grants (client_id);

-- ── device authorization sessions ────────────────────────────────────────
CREATE TABLE device_authorization_sessions (
  id                   TEXT PRIMARY KEY,
  device_code_hash     TEXT NOT NULL UNIQUE,
  user_code_hash       TEXT NOT NULL UNIQUE,
  client_id            TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  resource_uri         TEXT,
  scope                TEXT NOT NULL,
  status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
  user_id              TEXT REFERENCES users (id) ON DELETE SET NULL,
  expires_at           INTEGER NOT NULL,
  approved_at          INTEGER,
  denied_at            INTEGER,
  last_polled_at       INTEGER,
  poll_interval_seconds INTEGER NOT NULL DEFAULT 5,
  poll_count           INTEGER NOT NULL DEFAULT 0,
  created_at           INTEGER NOT NULL
);
CREATE INDEX idx_device_status ON device_authorization_sessions (status);
CREATE INDEX idx_device_expires ON device_authorization_sessions (expires_at);

-- ── audit logs (no FKs: must survive user/client deletion) ────────────────
CREATE TABLE audit_logs (
  id              TEXT PRIMARY KEY,
  event_type      TEXT NOT NULL,
  user_id         TEXT,
  client_id       TEXT,
  resource_uri    TEXT,
  request_id      TEXT,
  ip_hash         TEXT,
  user_agent_hash TEXT,
  scope           TEXT,
  success         INTEGER,
  detail          TEXT,
  metadata_json   TEXT,
  created_at      INTEGER NOT NULL
);
CREATE INDEX idx_audit_created ON audit_logs (created_at);
CREATE INDEX idx_audit_event ON audit_logs (event_type);
CREATE INDEX idx_audit_user ON audit_logs (user_id);
CREATE INDEX idx_audit_client ON audit_logs (client_id);

-- ── one-time email/password tokens (hash only; DO is consume authority) ───
CREATE TABLE email_verifications (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX idx_email_verif_user ON email_verifications (user_id);

CREATE TABLE password_reset_tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX idx_pwreset_user ON password_reset_tokens (user_id);
