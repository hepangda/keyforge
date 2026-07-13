-- 0008_oidc_logout.sql — RP-Initiated Logout redirect registrations.

ALTER TABLE oauth_clients
  ADD COLUMN post_logout_redirect_uris_json TEXT NOT NULL DEFAULT '[]';

UPDATE oauth_clients
SET post_logout_redirect_uris_json = CASE client_id
  WHEN 'pangda_app' THEN '["https://app.pangda.app/"]'
  WHEN 'pangda_admin' THEN '["https://admin.pangda.app/"]'
  ELSE '[]'
END;

-- OAuth 2.1 authorization-code requests are uniformly protected by S256 PKCE.
UPDATE oauth_clients SET require_pkce = 1 WHERE require_pkce != 1;
