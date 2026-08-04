-- Locally hosted user avatars. `picture` keeps its original meaning (an
-- externally hosted URL); when an uploaded avatar exists it takes precedence
-- and the `picture` claim points at this server's public avatar endpoint.
--
-- `avatar_key` is the unguessable R2 object key, which doubles as the public
-- URL path segment: possession of the URL is the read capability.

ALTER TABLE users ADD COLUMN avatar_key TEXT;
ALTER TABLE users ADD COLUMN avatar_content_type TEXT;
ALTER TABLE users ADD COLUMN avatar_updated_at INTEGER;

CREATE UNIQUE INDEX idx_users_avatar_key ON users (avatar_key) WHERE avatar_key IS NOT NULL;
