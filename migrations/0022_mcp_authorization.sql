-- MCP/OAuth resource capabilities and Client ID Metadata Document provenance.
-- Existing resources and clients remain unchanged and fail closed until an
-- administrator explicitly enables MCP behavior for a resource.

ALTER TABLE oauth_resources
  ADD COLUMN mcp_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mcp_enabled IN (0, 1));

ALTER TABLE oauth_resources
ADD COLUMN allow_metadata_clients INTEGER NOT NULL DEFAULT 0
  CHECK (
    allow_metadata_clients IN (0, 1)
    AND (allow_metadata_clients = 0 OR mcp_enabled = 1)
  );

ALTER TABLE oauth_clients
  ADD COLUMN registration_type TEXT NOT NULL DEFAULT 'static'
    CHECK (registration_type IN ('static', 'client_id_metadata'));

ALTER TABLE oauth_clients
  ADD COLUMN metadata_expires_at INTEGER;

CREATE INDEX idx_oauth_clients_metadata_expiry
  ON oauth_clients (metadata_expires_at, client_id)
  WHERE registration_type = 'client_id_metadata' AND enabled = 1;
