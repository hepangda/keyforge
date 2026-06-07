# Client Credentials

Machine-to-machine grant. No user, no refresh token.

```
POST /oauth/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=read:invoices
&resource=https://api.example.com
```

`scope` is checked against `client_allowed_scopes`; `resource` (RFC
8707) is checked against `client_allowed_resources`. Both default to
allow-only-when-explicitly-listed.
