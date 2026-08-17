import { describe, expect, it } from "vitest"
import example from "../../examples/mcp-server/src/index"

const ENV = {
  KEYFORGE_ISSUER: "http://127.0.0.1:17001",
  MCP_RESOURCE: "http://127.0.0.1:17002/mcp",
  MCP_INTROSPECTION_CLIENT_ID: "mcp_example_resource_server",
  MCP_INTROSPECTION_CLIENT_SECRET: "test-secret",
}

describe("MCP Worker example transport boundary", () => {
  it("publishes path-aware protected resource metadata", async () => {
    const response = await example.fetch(
      new Request("http://127.0.0.1:17002/.well-known/oauth-protected-resource/mcp"),
      ENV,
    )
    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({
      resource: ENV.MCP_RESOURCE,
      authorization_servers: [ENV.KEYFORGE_ISSUER],
      scopes_supported: ["mcp.tools.read", "mcp.tools.execute", "offline_access"],
    })
  })

  it("rejects cross-origin and non-JSON POST requests before authorization work", async () => {
    const crossOrigin = await example.fetch(
      new Request(ENV.MCP_RESOURCE, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://attacker.example" },
        body: "{}",
      }),
      ENV,
    )
    expect(crossOrigin.status).toBe(403)

    const wrongType = await example.fetch(
      new Request(ENV.MCP_RESOURCE, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "{}",
      }),
      ENV,
    )
    expect(wrongType.status).toBe(415)
  })
})
