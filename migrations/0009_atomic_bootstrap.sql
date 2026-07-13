-- Singleton claim used to make initial administrator creation atomic.
CREATE TABLE bootstrap_state (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  completed_at INTEGER NOT NULL,
  user_id      TEXT NOT NULL
);

-- Upgrades of an already-provisioned deployment must remain bootstrapped.
INSERT INTO bootstrap_state (id, completed_at, user_id)
SELECT 1, unixepoch(), u.id
FROM users u
JOIN user_groups ug ON ug.user_id = u.id
JOIN groups g ON g.id = ug.group_id
WHERE g.name = 'admins'
ORDER BY u.created_at ASC
LIMIT 1;
