BEGIN;

DROP TABLE IF EXISTS user_recovery_codes;
DROP TABLE IF EXISTS webauthn_challenges;
DROP TABLE IF EXISTS user_webauthn_credentials;
DROP TABLE IF EXISTS user_mfa_totp;

COMMIT;
