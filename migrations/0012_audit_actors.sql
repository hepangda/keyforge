-- Keep the event subject (user_id/client_id) separate from the authenticated
-- principal that performed an administrative action. No foreign keys are used
-- because audit evidence must survive actor or subject deletion.
ALTER TABLE audit_logs ADD COLUMN actor_user_id TEXT;
ALTER TABLE audit_logs ADD COLUMN actor_client_id TEXT;

-- Earlier administrative user events stored the actor in metadata. Backfill
-- only a valid JSON string, leaving malformed or unrelated metadata untouched.
UPDATE audit_logs
SET actor_user_id = json_extract(metadata_json, '$.actor_user_id')
WHERE metadata_json IS NOT NULL
  AND CASE
    WHEN json_valid(metadata_json)
    THEN json_type(metadata_json, '$.actor_user_id') = 'text'
    ELSE 0
  END;

-- Group/resource events historically used user_id for the administrator
-- because they have no user subject. Preserve that evidence in the actor
-- dimension without rewriting the original record.
UPDATE audit_logs
SET actor_user_id = user_id
WHERE actor_user_id IS NULL
  AND user_id IS NOT NULL
  AND event_type IN (
    'admin.group.created',
    'admin.group.updated',
    'admin.group.deleted',
    'admin.resource.created',
    'admin.resource.updated'
  );

CREATE INDEX idx_audit_actor_user_created
  ON audit_logs (actor_user_id, created_at DESC, id);
CREATE INDEX idx_audit_actor_client_created
  ON audit_logs (actor_client_id, created_at DESC, id);
