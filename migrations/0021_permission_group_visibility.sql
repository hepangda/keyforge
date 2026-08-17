-- Public permission groups are listed in the self-service request directory.
-- Hidden groups remain requestable only by an exact, manually entered name.

ALTER TABLE groups
ADD COLUMN is_public INTEGER NOT NULL DEFAULT 1 CHECK (is_public IN (0, 1));
