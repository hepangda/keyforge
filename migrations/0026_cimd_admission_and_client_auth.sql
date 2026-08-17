-- Resource-scoped CIMD admission, metadata provenance, consent versioning,
-- per-resource approvals, and private_key_jwt replay protection.

ALTER TABLE oauth_resources
ADD COLUMN metadata_client_policy TEXT NOT NULL DEFAULT 'disabled'
  CHECK (
    metadata_client_policy IN ('disabled', 'consent_required', 'admin_approved')
    AND (metadata_client_policy = 'disabled' OR mcp_enabled = 1)
  );

UPDATE oauth_resources
SET metadata_client_policy = CASE
  WHEN allow_metadata_clients = 1 THEN 'consent_required'
  ELSE 'disabled'
END;

-- The enum above is authoritative after this migration. Keep the historical
-- column inert because SQLite cannot safely drop a column referenced by its
-- original table-level compatibility constraint in place.
UPDATE oauth_resources SET allow_metadata_clients = 0;

ALTER TABLE oauth_clients ADD COLUMN metadata_fingerprint TEXT;
ALTER TABLE oauth_clients
  ADD COLUMN token_endpoint_auth_methods_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(token_endpoint_auth_methods_json));
ALTER TABLE oauth_clients ADD COLUMN metadata_jwks_uri TEXT;
ALTER TABLE oauth_clients
  ADD COLUMN introspection_allowed INTEGER NOT NULL DEFAULT 0
    CHECK (introspection_allowed IN (0, 1));

-- Preserve explicitly configured legacy confidential callers across the
-- capability cutover. Newly created clients are denied unless opted in.
UPDATE oauth_clients
SET introspection_allowed = 1
WHERE type = 'confidential' AND client_kind IN ('application', 'service');

UPDATE oauth_clients
SET token_endpoint_auth_methods_json = CASE
  WHEN registration_type = 'client_id_metadata' THEN '["none"]'
  WHEN type = 'public' THEN '["none"]'
  ELSE '["client_secret_basic","client_secret_post"]'
END;

UPDATE oauth_clients
SET metadata_fingerprint = 'legacy:' || client_id || ':' || updated_at
WHERE registration_type = 'client_id_metadata';

-- Older discovery code inserted application-only allows into the universal
-- group. Those rules bypass resource entitlement and must not survive the
-- resource-policy cutover.
DELETE FROM permission_group_rules
WHERE group_id = (SELECT id FROM groups WHERE name = 'all')
  AND effect = 'allow'
  AND json_extract(condition_json, '$.field') = 'application'
  AND json_extract(condition_json, '$.operator') = 'equals'
  AND json_extract(condition_json, '$.value') IN (
    SELECT client_id FROM oauth_clients WHERE registration_type = 'client_id_metadata'
  );

DELETE FROM oauth_client_permission_groups
WHERE group_id = (SELECT id FROM groups WHERE name = 'all')
  AND client_id IN (
    SELECT client_id FROM oauth_clients WHERE registration_type = 'client_id_metadata'
  );

ALTER TABLE consents ADD COLUMN metadata_fingerprint TEXT;

CREATE TABLE oauth_metadata_client_approvals (
  client_id           TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  resource_uri        TEXT NOT NULL REFERENCES oauth_resources (resource_uri) ON DELETE CASCADE,
  approved_by_user_id TEXT REFERENCES users (id) ON DELETE SET NULL,
  approved_at         INTEGER NOT NULL,
  PRIMARY KEY (client_id, resource_uri)
);
CREATE INDEX idx_metadata_client_approvals_resource
  ON oauth_metadata_client_approvals (resource_uri, client_id);

CREATE TABLE oauth_client_assertion_jtis (
  jti_hash   TEXT PRIMARY KEY,
  client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_client_assertion_jtis_expiry
  ON oauth_client_assertion_jtis (expires_at, client_id, jti_hash);
