# DPoP — Demonstrating Proof of Possession (RFC 9449)

Bind tokens to a per-client key pair so a stolen bearer is useless
without the matching private key.

Every protected request carries a `DPoP` header:

```
DPoP: <signed JWT with header { typ: dpop+jwt, alg: ES256, jwk: <pub> }
                         payload { jti, iat, htm: POST, htu: <full URL>, ath?: <SHA-256(AT)> }>
```

keyforge validates:

- `typ` is `dpop+jwt`, `alg` is asymmetric, `jwk` is public-only.
- `htm` and `htu` match the request.
- `iat` is within ±60 s of server time.
- `jti` has not been seen in the replay window (in-memory LRU by
  default, Postgres-backed for multi-replica deployments).
- For UserInfo/introspect, `ath` matches `base64url(sha256(access_token))`.

Tokens are stamped with `cnf.jkt = jwk.Thumbprint(SHA-256)`. The same
`jkt` must reappear on every subsequent use.

Bootstrap nonce: keyforge can require the client first hit the endpoint
without a proof to receive a `DPoP-Nonce` header, then retry with it
embedded in the proof.
