# Federation — Upstream OIDC

keyforge acts as the OIDC Relying Party against an upstream IdP and
links the result to a local user.

## Configuring an IdP

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_AT" \
  https://auth.example.com/admin/api/v1/idp \
  -d '{
    "slug":          "google",
    "display_name":  "Google",
    "issuer":        "https://accounts.google.com",
    "client_id":     "...apps.googleusercontent.com",
    "client_secret": "...",
    "scopes":        ["openid","profile","email"],
    "claim_mapping": {"subject":"sub","email":"email","display_name":"name"}
  }'
```

## Flow

```
1. Browser hits /oauth/login.
2. User clicks "Continue with Google".
3. Browser → /oauth/federation/google/start?ar=<auth_req>
4. keyforge stamps state+nonce+PKCE verifier onto the auth_request row,
   redirects to https://accounts.google.com/o/oauth2/v2/auth?...
5. User approves. Google redirects to /oauth/federation/google/callback.
6. keyforge validates the id_token (issuer, signature, nonce, audience),
   maps claims, and looks up / provisions the local user:
     a. existing (idp_id, subject) link → use that user
     b. else, email match in the tenant → link to existing user
     c. else, create a new user and link
7. Opens a session, attaches it to the original auth_request, redirects
   to /oauth/consent.
```

## Security notes

- Client secrets are envelope-encrypted at rest (same helper as JWKS).
- The upstream `id_token` is verified end-to-end; nothing in the
  callback URL is trusted on its own.
- PKCE is always used (S256) regardless of whether the upstream
  requires it.
