# MCP authorization

KeyForge can serve as the OAuth 2.1 authorization server for independently
deployed MCP servers. The MCP server remains the protected resource: it
publishes its own Protected Resource Metadata (PRM), challenges unauthenticated
requests, and validates bearer tokens through KeyForge's RFC 7662
introspection endpoint.

This design follows the
[MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728),
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), and
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662).

## Trust boundaries

1. The MCP client discovers PRM from the MCP server.
2. PRM names KeyForge in `authorization_servers` and lists the resource's
   scopes.
3. The client obtains user consent at KeyForge using authorization code + PKCE
   and sends the MCP resource URI in both the authorization and token requests.
4. KeyForge issues an access token whose `aud` is exactly that resource URI.
5. The MCP server sends the token to KeyForge's authenticated introspection
   endpoint. KeyForge rechecks the user, client, resource, consent, and current
   permission-group priorities and rules.
6. The MCP server enforces operation-specific scopes and its own object-level
   authorization.

The MCP server never accepts an ID token, refresh token, token for another
audience, or a locally trusted `sub` header. KeyForge never proxies MCP tool
calls and never receives their arguments or results.

## 1. Register the MCP resource

In the administrator console, open **APIs**, create the canonical MCP URL, add
the scopes the server understands, and enable **MCP authorization**. Production
resources must use HTTPS. Loopback HTTP is allowed for local development.

The same operation through the administrator API is:

```json
{
  "resource_uri": "https://mcp.example.com/mcp",
  "name": "Example MCP Server",
  "allowed_scopes": ["mcp.tools.read", "mcp.tools.execute"],
  "mcp_enabled": true,
  "metadata_client_policy": "consent_required"
}
```

`allowed_scopes` is owned by the resource and is not limited to KeyForge's
built-in Pangda scopes. `offline_access` controls refresh-token issuance; it is
not an MCP Resource Server capability and is intentionally absent from the
AAEasy MCP resource. Scope tokens must be unique, follow RFC 6749 syntax, and
stay within KeyForge's catalog bounds.

Under **Permission groups → Access**, add a base rule without a scope condition
that allows the MCP API, then add an explicit allow rule for every custom MCP
scope the group may receive. User authorization is default-deny at both stages.
CIMD discovery never inserts an application allow rule: successful metadata
validation is identity evidence, not user or Resource authorization.

Only matching rules at the smallest group priority number participate; a
same-priority deny wins. `openid`, `profile`, `email`, and `offline_access`
follow allowed base application/API access directly and cannot appear in scope
rules. Online introspection observes membership, priority, and rule changes on
the next request.

`metadata_client_policy` is `disabled`, `consent_required`, or
`admin_approved`, and any non-disabled value requires `mcp_enabled=true`.
`admin_approved` additionally requires a client/Resource approval through the
administrator API before authorization can continue.

## 2. Create an introspection credential

Create one confidential `service` client per MCP service or security boundary.
Set `introspection_allowed=true`, give it only the Resources it protects, and
do not grant it token issuance scopes or grant types.

```json
{
  "client_id": "example_mcp_introspector",
  "name": "Example MCP introspector",
  "type": "confidential",
  "client_kind": "service",
  "redirect_uris": [],
  "post_logout_redirect_uris": [],
  "allowed_scopes": [],
  "allowed_grant_types": [],
  "allowed_resources": ["https://mcp.example.com/mcp"],
  "default_resource": "https://mcp.example.com/mcp",
  "require_pkce": true,
  "introspection_allowed": true
}
```

The create response contains `client_secret` once. Put it in the MCP server's
secret manager; do not expose it to MCP clients, browser code, logs, or PRM.
Rotate it through `POST /admin/clients/:id/rotate-secret`.

## 3. Publish Protected Resource Metadata

For resource `https://mcp.example.com/mcp`, serve the document at:

```text
https://mcp.example.com/.well-known/oauth-protected-resource/mcp
```

Its body is:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["mcp.tools.read", "mcp.tools.execute", "offline_access"],
  "bearer_methods_supported": ["header"]
}
```

KeyForge publishes identical OAuth Authorization Server and OIDC discovery
metadata at:

```text
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

The metadata advertises PKCE S256, the token and introspection endpoints,
resource-owned scopes, and Client ID Metadata Document support.

## 4. Validate each MCP request

[`src/mcp/resource-server.ts`](../src/mcp/resource-server.ts) is the reusable
Cloudflare Workers adapter. Use it directly in the same workspace or vendor
the single module with `zod`. It builds PRM and
`WWW-Authenticate`, performs bounded/timeout-protected introspection, verifies
exact issuer and audience, checks expiry and access-token type, and returns
identity/scope context.

```ts
import {
  authorizeMcpRequest,
  mcpProtectedResourceMetadataResponse,
  mcpResourceMetadataUrl,
} from "../keyforge/src/mcp/resource-server"

const authorization = await authorizeMcpRequest(request, ["mcp.tools.read"], {
  resource: env.MCP_RESOURCE,
  authorizationServers: [env.KEYFORGE_ISSUER],
  scopesSupported: ["mcp.tools.read", "mcp.tools.execute", "offline_access"],
  issuer: env.KEYFORGE_ISSUER,
  introspectionEndpoint: `${env.KEYFORGE_ISSUER}/oauth/introspect`,
  clientId: env.MCP_INTROSPECTION_CLIENT_ID,
  clientSecret: env.MCP_INTROSPECTION_CLIENT_SECRET,
})

if (!authorization.ok) return authorization.response
```

Use the returned `subject`, `clientId`, and `scopes` as inputs to application
authorization. Require the smallest scope at each tool, prompt, resource, and
data-object boundary; a successful baseline check is not permission to run
every tool.

The adapter returns:

- `401` plus `WWW-Authenticate` and `resource_metadata` for missing, inactive,
  expired, malformed, wrong-issuer, or wrong-audience tokens.
- `403` plus `insufficient_scope` and the required scope set when the token is
  valid but lacks permission for the operation.
- `503` and `Retry-After` when introspection is unavailable or malformed. It
  never fails open or caches an active decision.

The adapter is intentionally online. This means disabling a user/client/API,
removing group membership, or revoking consent takes effect on the next MCP
request rather than waiting for JWT expiry.

## Client registration

Administrators can pre-register normal public application clients. For open
MCP ecosystems, select a non-disabled metadata client policy. KeyForge accepts
an HTTPS document URL as `client_id`, follows at most three manually validated
HTTPS redirects, validates every DNS target against special-use address ranges,
bounds JSON to 5 KiB, and requires exact redirect URI matching, PKCE S256, and
authorization code.

Metadata may advertise `none`, `private_key_jwt`, or both with
`token_endpoint_auth_methods_supported`. The legacy singular preference is
accepted only when it is in that set. `private_key_jwt` requires a same-origin
`jwks_uri`; assertions are signature-, issuer-, subject-, audience-, lifetime-,
and replay-checked.

```json
{
  "client_id": "https://client.example.com/oauth/client.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://127.0.0.1:49152/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://client.example.com/oauth/jwks.json"
}
```

The `client_id` must exactly equal the document URL. Wildcards, credentials,
query, fragment, and dot segments are rejected. Redirect URIs may be HTTPS or
loopback HTTP. Consent displays the complete client identity, callback,
Resource, permissions, metadata changes, and localhost warning.

Discovery is protected by a per-source rate limit, a 10,000-record cap, bounded
cache TTL, and scheduled cleanup. `registration_type=client_id_metadata`, a
metadata fingerprint, and read-only management fields keep external metadata
distinct from administrator registrations. Fingerprint changes invalidate
remembered consent and revoke grants and refresh tokens without converting the
client into a trusted application.

KeyForge supports pre-registration and CIMD. It does not publish a DCR
`registration_endpoint`: MCP 2026-07-28 deprecates DCR, while current ChatGPT
and Codex support CIMD with `none` and `private_key_jwt`. Add a separately
flagged, Resource-scoped DCR fallback only after a target client demonstrates a
real CIMD incompatibility.

## Token requests

MCP clients must include the exact resource in the authorization request and
again when redeeming an authorization code:

```text
resource=https%3A%2F%2Fmcp.example.com%2Fmcp
```

KeyForge rejects an omitted or mismatched value before issuing a token. The
same exact `resource` is required when using a refresh token for an
MCP-enabled resource. Access tokens contain that value as `aud`; an MCP server
must never accept tokens issued for KeyForge's Admin API or another MCP server.

## Runnable Worker example

[`examples/mcp-server`](../examples/mcp-server) is a standalone HTTP MCP Worker
that publishes PRM, supports `initialize`, `tools/list`, and `tools/call`, and
uses KeyForge introspection before parsing or dispatching a tool call. It also
validates the HTTP `Origin`, JSON media type, protocol version, and request size
at the transport boundary.

For local development:

1. Run KeyForge on `http://localhost:17001` and register
   `http://localhost:17002/mcp` as an MCP resource.
2. Create the confidential service client described above and assign its
   `client_id` in `examples/mcp-server/wrangler.toml`.
3. Put the one-time secret in
   `examples/mcp-server/.dev.vars` as
   `MCP_INTROSPECTION_CLIENT_SECRET=...`.
4. Run `pnpm dev:mcp-example`; it listens on port `17002`.

Use an administrator-pre-registered public application for a fully local OAuth
client. Client Identifier URLs themselves require public HTTPS and therefore
are not accepted from localhost.

## Production checklist

- Apply D1 migration `0022_mcp_authorization.sql` before deploying the Worker.
- Keep the resource URI byte-for-byte identical in KeyForge, PRM, client
  authorization/token requests, the adapter, and the access-token audience.
- Store each introspection secret separately and restrict its
  `allowed_resources` to least privilege.
- Do not log Authorization headers, tokens, client secrets, authorization
  codes, metadata document bodies, or MCP tool arguments containing secrets.
- Protect tool execution with operation- and object-level authorization after
  the adapter succeeds.
- Monitor introspection `401`/`403` rates and `503` availability failures.
- Test membership removal, consent revocation, client disablement, resource
  disablement, secret rotation, and KeyForge outage behavior before launch.
