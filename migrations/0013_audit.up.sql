-- 0013_audit: append-only audit log.
--
-- One row per state-changing admin action and per security-relevant
-- end-user action (login, MFA enrollment, consent grant). The table is
-- INSERT-only — admins read it; deletes happen only via TTL purge from
-- a separate job (not in v1 scope).

BEGIN;

CREATE TABLE audit_log (
    id              BIGSERIAL    PRIMARY KEY,
    tenant_id       UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Exactly one of actor_user_id / actor_client_id is typically set:
    -- a human admin via UI, or a machine actor via /oauth/token.
    actor_user_id   UUID         REFERENCES users(id) ON DELETE SET NULL,
    actor_client_id UUID         REFERENCES clients(id) ON DELETE SET NULL,
    action          TEXT         NOT NULL,
    target_type     TEXT         NOT NULL,
    target_id       TEXT,
    ip              TEXT,
    user_agent      TEXT,
    request_id      TEXT,
    attributes      JSONB        NOT NULL DEFAULT '{}'::JSONB,
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_log_tenant_occurred_idx ON audit_log(tenant_id, occurred_at DESC);
CREATE INDEX audit_log_actor_user_idx      ON audit_log(actor_user_id) WHERE actor_user_id IS NOT NULL;
CREATE INDEX audit_log_actor_client_idx    ON audit_log(actor_client_id) WHERE actor_client_id IS NOT NULL;
CREATE INDEX audit_log_action_idx          ON audit_log(action);
CREATE INDEX audit_log_target_idx          ON audit_log(target_type, target_id) WHERE target_id IS NOT NULL;

-- Reinforce intent: revoke UPDATE/DELETE for the keyforge role at the
-- database layer. We grant INSERT/SELECT but not UPDATE/DELETE on the
-- audit_log table. (Run as a separate REVOKE so the migration tool can
-- own this even if the user is repaired.)
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

UPDATE schema_meta SET version = '0013_audit', applied_at = NOW();

COMMIT;
