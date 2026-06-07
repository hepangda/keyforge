# PAR — Pushed Authorization Requests (RFC 9126)

Push the authorization request server-to-server first, then redirect
the browser to a tiny URL referencing the stored payload.

```
POST /oauth/par
Authorization: client auth
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=...
&redirect_uri=...
&scope=...
&state=...
&code_challenge=...
&code_challenge_method=S256

→ 201 { "request_uri": "urn:ietf:params:oauth:request_uri:<opaque>",
        "expires_in": 90 }
```

Then drive the browser to:

```
GET /oauth/authorize?client_id=<id>&request_uri=<above>
```

PAR requests are **single use** and consumed by `/oauth/authorize`. A
client can be forced to use PAR by setting `require_par=true` on its
record.
