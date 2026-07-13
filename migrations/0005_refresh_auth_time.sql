-- Preserve the original authentication instant across refresh-token rotation.
-- Existing families predate this column, so use their creation time as the
-- closest available authentication instant during the one-time backfill.
ALTER TABLE refresh_tokens ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;

UPDATE refresh_tokens SET auth_time = created_at WHERE auth_time = 0;
