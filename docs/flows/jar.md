# JAR — JWT-Secured Authorization Request (RFC 9101)

Carry the authorization request as a signed JWT (`request` parameter).
The same key-resolution path as `private_key_jwt` is used to verify
the signature.

```
GET /oauth/authorize?client_id=<id>&request=<signed JWT>
```

The JWT MUST contain:

- `iss` == `client_id`
- `aud` == the authorization endpoint URL
- one of `jwks` / `jwks_uri` resolvable for `client_id`
- the OAuth params (`response_type`, `redirect_uri`, …) as claims

JAR composes with PAR: push a JAR JWT inside `/oauth/par`, then redeem
the resulting `request_uri`.
