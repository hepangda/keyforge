-- One local account may bind at most one identity from each provider.
-- Deliberately fail the migration when legacy duplicates exist so operators
-- can inspect and resolve them; an identity migration must never delete a
-- user's login method silently.

CREATE UNIQUE INDEX idx_identities_user_provider
  ON identities (user_id, provider);
