# Authorization Code + PKCE

The default browser flow for public clients (SPAs, mobile apps) and the
recommended choice for confidential clients too.

## Wire shape

```
GET /oauth/authorize?
  response_type=code
  &client_id=<id>
  &redirect_uri=<exact match>
  &scope=openid+profile+email
  &state=<random>
  &nonce=<random>
  &code_challenge=<base64url(sha256(verifier))>
  &code_challenge_method=S256
```

User authenticates + consents → keyforge redirects:

```
HTTP/1.1 302 Found
Location: <redirect_uri>?code=<32B-base64url>&state=<echoed>
```

Then:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=<exact match used above>
&client_id=<id>
&code_verifier=<original verifier>
```

Response:

```json
{
  "access_token":  "kf_at_<opaque>",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "kf_rt_<opaque>",
  "id_token":      "<jwt>",
  "scope":         "openid profile email"
}
```

## Hard rules

- PKCE is **mandatory** for public clients and accepted for confidential
  clients. `plain` is rejected; only S256 is accepted.
- The redirect URI must be an **exact match** (RFC 8252 loopback
  exception applies for `http://127.0.0.1`).
- The authorization code is single-use, expires after 60 s, and is
  rejected on replay.
- `id_token.nonce` always echoes the request's `nonce`; the SPA verifies
  it matches the value it persisted before the redirect.
