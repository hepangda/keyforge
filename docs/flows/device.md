# Device Flow (RFC 8628)

For CLIs and TVs. Two endpoints: `/device_authorization` (mint) and
`/oauth/token` (poll).

```
POST /device_authorization
client_id=demo-cli

→ 200 {
  "device_code":    "<opaque>",
  "user_code":      "WDJB-MJHT",
  "verification_uri":          "https://auth.example.com/device",
  "verification_uri_complete": "https://auth.example.com/device?user_code=WDJB-MJHT",
  "interval":  5,
  "expires_in": 600
}
```

Then poll `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
until you see one of: `authorization_pending`, `slow_down`,
`access_denied`, `expired_token`, or a token bundle on success.
