# Administrator API

The JSON administrator API is served under `/admin`. It is intended for the
first-party console and trusted operational tooling, not for public OAuth
clients.

## Authentication and mutation protection

Every endpoint requires a valid KeyForge session whose user belongs to the
`admins` group. A missing session returns `401`; a non-admin session returns
`403`.

Cookie-authenticated mutations also require request-integrity validation.
Same-origin browser requests pass the Origin/Fetch Metadata check. Scripts and
other non-browser clients must first call `GET /admin/csrf` with the session
cookie, then echo the returned `csrf_token` in the `x-keyforge-csrf` header while
retaining the CSRF and session cookies.

```bash
curl -c cookies.txt -b cookies.txt https://auth.pangda.app/admin/csrf
curl -c cookies.txt -b cookies.txt \
  -H 'content-type: application/json' \
  -H "x-keyforge-csrf: $CSRF_TOKEN" \
  -X PATCH https://auth.pangda.app/admin/users/usr_example \
  --data '{"disabled":true}'
```

JSON validation failures return `400 {"error":"invalid_request"}`. Missing
objects return `404 {"error":"not_found"}`. Pagination uses `limit` and
`offset`; the server bounds values to its safe limits.

## CSRF token

### `GET /admin/csrf`

Returns `{ "csrf_token": "..." }` and sets the double-submit cookie used by
non-browser mutation requests.

## Users

### `GET /admin/users?limit=50&offset=0`

Lists users. Password hashes, passkey material, and session tokens are never
returned.

### `POST /admin/users`

Creates a login-ready user. `email` and `alias` are required. Aliases are
case-insensitively unique and may contain English letters, numbers, hyphens,
and underscores. When a `password` is supplied it must contain 6–128
characters, or at least 12 when the user is created in the `admins` group;
otherwise the server sends a
one-time account invitation through the configured email provider.

```json
{
  "email": "ada@example.com",
  "alias": "adalovelace",
  "name": "Ada Lovelace",
  "email_verified": false,
  "password": "optional-initial-password",
  "group_ids": ["grp_seed_employees"]
}
```

The response reports `credential_setup` as `password_set` or
`invitation_sent`. Duplicate email or alias returns `409`; invalid group IDs
return `400`. The optional `group_ids` array accepts at most 100 entries.

### `GET /admin/users/:id`

Returns one user plus its `groups` array. `picture` is the effective avatar URL
(an uploaded avatar takes precedence over an externally hosted one) and
`has_avatar` reports whether the account has an uploaded avatar. The returned `id` is the user's stable,
unique identifier and is also emitted as the standard `sub` claim in ID Tokens.

### `PATCH /admin/users/:id`

Accepts any subset of the mutable fields below. Only administrators can change
the username (`alias`); there is no self-service username update endpoint.

```json
{
  "alias": "ada",
  "name": "Ada Lovelace",
  "disabled": false,
  "emailVerified": true
}
```

Changing `alias` changes the value accepted at username sign-in and the
`preferred_username` claim issued in future tokens. It can therefore disrupt
saved sign-in details, external mappings, or automation that treats that claim
as a key. The stable user `id` and ID Token `sub` do not change. Invalid aliases
return `400`; a case-insensitive alias conflict returns
`409 {"error":"duplicate_alias"}`.

Disabling a user also revokes active sessions and refresh-token access. The API
returns `409 {"error":"last_active_admin"}` rather than disabling the sole
active administrator.

### `PUT /admin/users/:id/groups`

Replaces all group memberships with `{ "group_ids": ["..."] }`, with at most
100 entries. Unknown group IDs or oversized arrays return `400`. Removing the
`admins` group from the sole active administrator returns `409`.

### `POST /admin/users/:id/revoke-sessions`

Revokes the user's active sessions and associated refresh-token access. Returns
`{ "revoked": true }`.

### `GET /admin/users/:id/login-methods`

Returns password and passkey summaries in one response. Password hashes and
passkey public keys are never included.

### `POST /admin/users/:id/passwords`

Adds another password login method from
`{ "name": "Recovery password", "password": "..." }`. A user may keep up to
five passwords. The 6-character minimum applies to ordinary users and the
12-character minimum applies to administrators.

### `DELETE /admin/users/:id/passwords/:credentialId`

Deletes one password if another password or passkey remains. Attempting to
remove the final reusable login method returns `409`.

### `DELETE /admin/users/:id/passkeys/:credentialId`

Deletes one passkey under the same last-login-method guard.

### `PUT /admin/users/:id/avatar`

Replaces a user's avatar. Send the raw image bytes as the request body, or a
`multipart/form-data` body with the image in an `avatar` field. PNG, JPEG,
WebP, and GIF are accepted up to 3 MB; the type is determined from the file's
magic bytes, so the request `content-type` is not trusted and SVG is rejected.
Returns `{ "picture": "...", "content_type": "image/png" }`. Oversized uploads
return `413`, unsupported or empty bodies return `400`.

The returned `picture` URL contains an unguessable object key and is publicly
readable, which is what lets a relying party place the `picture` claim straight
into an `<img>` tag. Replacing or removing an avatar issues a new key and makes
the old URL stop resolving.

### `DELETE /admin/users/:id/avatar`

Removes the user's avatar and its stored object. Returns
`{ "deleted": true }`, or `{ "deleted": false }` if no avatar was set.

### `POST /admin/users/:id/magic-link`

Generates and returns a one-time 15-minute sign-in URL for an existing, enabled
user. The URL is returned only in this response and is never generated for an
unknown or disabled account.

## Permission groups

### `GET /admin/groups`

Lists group IDs, names, descriptions, and current member counts.

### `POST /admin/groups`

Creates a group from `{ "name": "operators", "description": "..." }`. Names
are lowercase identifiers containing letters, digits, `.`, `_`, `:`, or `-`.
A duplicate name returns `409`.

### `GET /admin/groups/:id`

Returns one group including its current member count.

### `GET /admin/groups/:id/access`

Returns the permission group's deterministic, sorted target assignments:

```json
{
  "client_ids": ["pangda_app"],
  "resource_uris": ["https://api.pangda.app"]
}
```

### `PUT /admin/groups/:id/access`

Atomically replaces both target sets using the same shape as the `GET`
response. Both arrays are required and accept at most 100 entries each. Client
targets must be existing `application` or `device` clients; service clients and
unknown clients or resources return `400 { "error": "invalid_access_target" }`
without changing either set. An unknown group returns `404`.

User-token authorization is default-deny. A current user membership must match
at least one group assigned to the application and at least one group assigned
to the API; different memberships may satisfy those independent checks. Empty
sets grant no access. Renaming a group preserves its assignments because rules
reference its stable ID. The protected `admins` group can manage these target
assignments even though its name cannot change.

### `PATCH /admin/groups/:id`

Updates `name` and/or `description`. The built-in `admins` group cannot be
renamed, and group names remain globally unique.

### `DELETE /admin/groups/:id`

Deletes a non-protected permission group and cascades its memberships plus its
application and API assignments. Deleting a group, client, or resource cannot
grant access: cascaded assignments leave the affected target default-denied
when no matching assignment remains. The built-in `admins` group cannot be
deleted.

## OAuth clients

### `GET /admin/clients`

Lists OAuth clients and whether each client has a secret. Secret hashes and
previous plaintext secrets are never returned.

### `POST /admin/clients`

Creates a coherent client policy. Required fields are `client_id`, `name`,
`type`, `client_kind`, at least one supported scope and grant, and at least one
registered, enabled resource. `default_resource`, when present, must be one of
the allowed resources. Client IDs are URL-safe identifiers of at most 128
characters.

```json
{
  "client_id": "inventory_service",
  "name": "Inventory Service",
  "type": "confidential",
  "client_kind": "service",
  "redirect_uris": [],
  "post_logout_redirect_uris": [],
  "allowed_scopes": ["api.read"],
  "allowed_grant_types": ["client_credentials"],
  "allowed_resources": ["https://api.pangda.app"],
  "default_resource": "https://api.pangda.app",
  "require_pkce": true
}
```

A confidential client receives `client_secret` exactly once in the `201`
response. Store it in the consumer's secret manager immediately.
Post-logout redirects must use HTTPS, except loopback HTTP is accepted for
local development; credentials and URI fragments are rejected.

Application clients require authorization code, at least one redirect, and may
optionally use refresh tokens. Device clients require the device-code grant and
no redirects. Service clients must be confidential, use only client credentials,
and cannot request user-only scopes. Public clients cannot use client credentials;
`offline_access` requires the refresh-token grant.

### `PATCH /admin/clients/:id`

Updates `name`, redirect URIs, post-logout redirect URIs, scopes, grant types,
resources, or the default resource. PKCE with `S256` is mandatory for every
authorization-code client; `require_pkce: false` is rejected rather than
creating a per-client downgrade.

### `DELETE /admin/clients/:id`

Deletes a client and its dependent grants/consents according to D1 foreign-key
rules.

### `POST /admin/clients/:id/rotate-secret`

Replaces a confidential client's secret and returns the new value exactly once.

### `POST /admin/clients/:id/disable`

### `POST /admin/clients/:id/enable`

Toggles issuance eligibility without deleting the client.

## Resources

### `GET /admin/resources`

Lists protected resource identifiers and their scope policies.

### `POST /admin/resources`

```json
{
  "resource_uri": "https://inventory.pangda.app",
  "name": "Inventory API",
  "allowed_scopes": ["api.read"]
}
```

### `PATCH /admin/resources/:id`

Updates `name`, `allowed_scopes`, or `enabled`. URL-encode a resource URI when
placing it in the path.

### `DELETE /admin/resources/:id`

Deletes a registered API resource; URL-encode its resource URI in the path.
Deletion cascades permission-group assignments, removes the URI from every
client's allowed resources, clears matching default resources and consents,
revokes matching refresh/grant records, and denies pending or approved device
requests. Already-issued self-contained access tokens remain valid until their
normal expiry. An unknown resource returns `404`.

## Audit and device sessions

### `GET /admin/audit-logs`

Supports `limit`, `offset`, `user_id`, `client_id`, `actor_user_id`,
`actor_client_id`, and `event_type` filters. Each entry returns the actor fields
separately from the subject `user_id`/`client_id`, so an administrator changing
another account is attributable without overwriting the affected account.
These fields remain restricted to the authenticated administrator API and
console; sensitive token and credential material is not returned.

### `GET /admin/device-sessions`

### `GET /admin/device-sessions/:id`

Lists or retrieves CLI/device authorization sessions.

### `POST /admin/device-sessions/:id/revoke`

Denies a pending or approved device session. Returns `{ "revoked": true }`.
