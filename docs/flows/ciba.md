# CIBA — Client-Initiated Backchannel Authentication

Out-of-band approval flow. keyforge implements **poll mode** in v1.

```
POST /bc-authorize
Authorization: client auth (any of the 5 methods)

login_hint=user@example.com
&scope=openid profile
&binding_message="Sign in to Acme: 4329"

→ 200 { "auth_req_id": "<opaque>", "expires_in": 120, "interval": 5 }
```

The user receives a portal notification; once they approve, poll
`/oauth/token`:

```
grant_type=urn:openid:params:grant-type:ciba
&auth_req_id=<above>
```

Pending responses use the same `authorization_pending` / `slow_down`
shape as the device flow.
