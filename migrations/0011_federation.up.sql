-- 0011_federation: upstream OIDC IdP connectors and federated identity links.
--
-- idp_connectors:      one row per upstream IdP enabled in a tenant. The
--                      client secret is sealed with the same envelope helper
--                      as JWKS private keys.
-- federated_identity:  binds an upstream subject to a local user. A given
--                      (idp_id, subject) is unique per tenant.

BEGIN;

CREATE TABLE idp_connectors (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Stable per-tenant slug used in URLs: /oauth/federation/{slug}/start
    slug              TEXT        NOT NULL,
    display_name      TEXT        NOT NULL,
    issuer            TEXT        NOT NULL,
    client_id         TEXT        NOT NULL,
    -- Envelope-encrypted client secret (DEK + ciphertext). Null when the
    -- upstream client is configured with PKCE-only / no secret.
    secret_ciphertext BYTEA,
    dek_ciphertext    BYTEA,
    scopes            TEXT[]      NOT NULL DEFAULT ARRAY['openid','profile','email']::TEXT[],
    -- Claim mapping is a JSONB shape like:
    --   {"email":"email","display_name":"name","subject":"sub"}
    -- Keys are local field names; values are upstream claim names. The
    -- mapper falls back to the same name on either side when the value is
    -- empty.
    claim_mapping     JSONB       NOT NULL DEFAULT '{}'::JSONB,
    enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, slug)
);

CREATE INDEX idp_connectors_tenant_idx ON idp_connectors(tenant_id);

CREATE TABLE federated_identity (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_id      UUID        NOT NULL REFERENCES idp_connectors(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject     TEXT        NOT NULL,
    linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    UNIQUE (tenant_id, idp_id, subject)
);

CREATE INDEX federated_identity_user_idx ON federated_identity(user_id);
CREATE INDEX federated_identity_tenant_idx ON federated_identity(tenant_id);

-- The federation flow needs to remember state, nonce, and PKCE verifier
-- between /start and /callback. Reuse the auth_requests row for this so
-- the inbound /oauth/authorize request that triggered federation is
-- preserved end-to-end.
ALTER TABLE auth_requests
    ADD COLUMN federation_idp_id      UUID,
    ADD COLUMN federation_state       TEXT,
    ADD COLUMN federation_nonce       TEXT,
    ADD COLUMN federation_pkce_verifier TEXT;

UPDATE schema_meta SET version = '0011_federation', applied_at = NOW();

COMMIT;
