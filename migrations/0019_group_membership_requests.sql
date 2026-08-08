-- Self-service permission-group join requests. A row represents one pending
-- request; approval, rejection, or cancellation removes it.

CREATE TABLE group_membership_requests (
  user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  group_id     TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  requested_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, group_id)
);

CREATE INDEX idx_group_membership_requests_group
  ON group_membership_requests (group_id, requested_at, user_id);
CREATE INDEX idx_group_membership_requests_user
  ON group_membership_requests (user_id, requested_at, group_id);

CREATE TRIGGER clear_group_membership_request_after_join
AFTER INSERT ON user_groups
BEGIN
  DELETE FROM group_membership_requests
  WHERE user_id = NEW.user_id AND group_id = NEW.group_id;
END;
