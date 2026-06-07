-- 0010_mfa: per-user MFA factors.
--
-- user_mfa_totp:               one TOTP secret per user (envelope-encrypted)
-- user_webauthn_credentials:   N WebAuthn / FIDO2 credentials per user
-- webauthn_challenges:         short-lived per-session WebAuthn challenges
-- user_recovery_codes:         single-use bcrypt-hashed recovery codes

BEGIN;

CREATE TABLE user_mfa_totp (
    user_id          UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The TOTP secret as a wrapped (DEK, ciphertext) pair, encrypted via
    -- the same envelope helper jwks uses.
    secret_ciphertext  BYTEA     NOT NULL,
    dek_ciphertext     BYTEA     NOT NULL,
    algorithm        TEXT        NOT NULL DEFAULT 'SHA1',  -- pquerna/otp default
    digits           INTEGER     NOT NULL DEFAULT 6,
    period_seconds   INTEGER     NOT NULL DEFAULT 30,
    -- Until the user proves they configured their authenticator with the
    -- secret, confirmed_at remains NULL and the factor doesn't count.
    confirmed_at     TIMESTAMPTZ,
    last_used_at     TIMESTAMPTZ,
    -- Anti-replay window: the most recent successfully-verified counter,
    -- which equals floor(unix_time / period). Re-presenting the same
    -- counter is rejected.
    last_counter     BIGINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_mfa_totp_tenant_idx ON user_mfa_totp(tenant_id);

CREATE TABLE user_webauthn_credentials (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id     BYTEA       NOT NULL,
    public_key        BYTEA       NOT NULL,
    sign_count        BIGINT      NOT NULL DEFAULT 0,
    aaguid            BYTEA,
    transports        TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    attestation_type  TEXT,
    nickname          TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at      TIMESTAMPTZ,
    UNIQUE (user_id, credential_id)
);

CREATE INDEX user_webauthn_credentials_tenant_idx ON user_webauthn_credentials(tenant_id);
CREATE INDEX user_webauthn_credentials_user_idx ON user_webauthn_credentials(user_id);

CREATE TABLE webauthn_challenges (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID        REFERENCES users(id) ON DELETE CASCADE,
    -- Whichever ceremony minted this challenge.
    ceremony        TEXT        NOT NULL CHECK (ceremony IN ('register','assert')),
    -- JSON blob: the SessionData that go-webauthn handed us at Begin* time.
    session_data    JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX webauthn_challenges_tenant_idx ON webauthn_challenges(tenant_id);
CREATE INDEX webauthn_challenges_expires_idx ON webauthn_challenges(expires_at);

CREATE TABLE user_recovery_codes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT        NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_recovery_codes_tenant_user_idx ON user_recovery_codes(tenant_id, user_id);
CREATE INDEX user_recovery_codes_hash_idx ON user_recovery_codes(code_hash);

UPDATE schema_meta SET version = '0010_mfa', applied_at = NOW();

COMMIT;
