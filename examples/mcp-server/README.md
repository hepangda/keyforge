# KeyForge MCP server example

This standalone Cloudflare Worker demonstrates a protected HTTP MCP server
backed by KeyForge authorization. It publishes RFC 9728 metadata, validates
every request through KeyForge introspection, and enforces a stronger scope on
`tools/call` than on discovery/listing.

See [the MCP authorization guide](../../docs/mcp.md) for KeyForge resource and
service-client setup, local configuration, protocol behavior, and the
production checklist.

Copy `.dev.vars.example` to `.dev.vars`, insert the one-time introspection
client secret, then run `pnpm dev:mcp-example` from the repository root.
