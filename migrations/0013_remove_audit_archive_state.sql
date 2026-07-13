-- R2 audit archiving was removed. Delete obsolete pagination cursors so D1
-- contains no control state for a storage system the Worker no longer uses.
DELETE FROM maintenance_state
WHERE key IN ('audit_archive_prune_cursor', 'audit_archive_prune_cursor_v2');
