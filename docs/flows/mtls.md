# mTLS — Certificate-Bound Access Tokens (RFC 8705 §3)

When the client authenticates via `tls_client_auth` or
`self_signed_tls_client_auth`, the issued access token is bound to the
SHA-256 thumbprint of the presenting certificate (`cnf.x5t#S256`).

## Wire shape

```
POST /oauth/token (on the mTLS listener, port 8443 by default)
[client presents X.509 cert]

→ token includes "cnf": { "x5t#S256": "<base64url thumbprint>" }
```

Subsequent UserInfo/introspect/resource calls must present the same
certificate; keyforge re-computes the thumbprint and rejects on
mismatch.

## Trusted-proxy hardening

When the TLS termination happens at an ingress / sidecar (Envoy, nginx)
the leaf cert arrives in an `X-Forwarded-Client-Cert` header. **The
ingress MUST strip any client-supplied value** before keyforge sees it.

### nginx-ingress

```nginx
proxy_set_header X-Forwarded-Client-Cert "";
proxy_set_header X-Forwarded-Client-Cert $ssl_client_cert;
```

### Envoy

```yaml
forward_client_cert_details: SANITIZE_SET
set_current_client_cert_details:
  cert: true
```

keyforge will refuse to start with `mtls.Header` mode unless the
config's `security.trusted_proxies` lists the ingress's CIDR.
