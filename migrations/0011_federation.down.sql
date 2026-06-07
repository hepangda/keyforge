BEGIN;

ALTER TABLE auth_requests
    DROP COLUMN IF EXISTS federation_pkce_verifier,
    DROP COLUMN IF EXISTS federation_nonce,
    DROP COLUMN IF EXISTS federation_state,
    DROP COLUMN IF EXISTS federation_idp_id;

DROP TABLE IF EXISTS federated_identity;
DROP TABLE IF EXISTS idp_connectors;

COMMIT;
