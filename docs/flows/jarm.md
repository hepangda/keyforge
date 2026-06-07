# JARM — JWT-Secured Authorization Response Mode

Wrap the authorization response in a signed JWT so the RP can verify
the issuer + integrity instead of trusting raw query parameters.

Set `response_mode` to one of: `jwt`, `query.jwt`, `fragment.jwt`,
`form_post.jwt` (or configure `authorization_signed_response_alg` on
the client to default to `query.jwt`).

The response is a single `response=<jwt>` parameter; the JWT payload:

```json
{
  "iss":   "https://auth.example.com",
  "aud":   "<client_id>",
  "exp":   1700000000,
  "code":  "<authorization code>",
  "state": "<echoed>"
}
```

On `error` responses the JWT carries `error` + `error_description` +
`state` instead of `code`.
