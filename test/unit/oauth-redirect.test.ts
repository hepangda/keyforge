import { describe, expect, it } from "vitest"
import { isRegisteredRedirectUri } from "../../src/oauth/redirect"
import { asClientId, type OAuthClient } from "../../src/types/domain"

function client(
  registrationType: OAuthClient["registrationType"],
  redirectUris: readonly string[],
): OAuthClient {
  return {
    clientId: asClientId("test_client"),
    name: "Test client",
    type: "public",
    clientKind: "application",
    clientSecretHash: null,
    redirectUris,
    postLogoutRedirectUris: [],
    allowedScopes: ["mcp.tools.read"],
    allowedGrantTypes: ["authorization_code"],
    allowedResources: ["https://mcp.example.com/mcp"],
    defaultResource: "https://mcp.example.com/mcp",
    requirePkce: true,
    enabled: true,
    tokenEndpointAuthMethods: ["none"],
    introspectionAllowed: false,
    registrationType,
    metadataFingerprint: registrationType === "client_id_metadata" ? "fingerprint" : null,
    metadataExpiresAt: registrationType === "client_id_metadata" ? 1_800_000_000 : null,
    metadataJwksUri: null,
  }
}

describe("isRegisteredRedirectUri", () => {
  it("keeps exact redirect URI matching for every client", () => {
    const metadataClient = client("client_id_metadata", ["https://client.example.com/callback"])
    expect(isRegisteredRedirectUri(metadataClient, "https://client.example.com/callback")).toBe(
      true,
    )
    expect(isRegisteredRedirectUri(metadataClient, "https://client.example.com:444/callback")).toBe(
      false,
    )
  })

  it.each([
    ["http://127.0.0.1/callback/codex", "http://127.0.0.1:50972/callback/codex"],
    ["http://[::1]/callback/codex", "http://[::1]:50972/callback/codex"],
  ])("allows an ephemeral port for a CIMD loopback IP redirect", (registered, presented) => {
    expect(isRegisteredRedirectUri(client("client_id_metadata", [registered]), presented)).toBe(
      true,
    )
  })

  it("does not relax loopback ports for statically registered clients", () => {
    const staticClient = client("static", ["http://127.0.0.1/callback/codex"])
    expect(isRegisteredRedirectUri(staticClient, "http://127.0.0.1:50972/callback/codex")).toBe(
      false,
    )
  })

  it.each([
    "http://localhost:50972/callback/codex",
    "http://127.0.0.1:50972/callback/other",
    "http://127.0.0.1:50972/callback/codex?next=other",
    "https://127.0.0.1:50972/callback/codex",
  ])("rejects a loopback redirect that differs by more than its port: %s", (presented) => {
    const metadataClient = client("client_id_metadata", ["http://127.0.0.1/callback/codex"])
    expect(isRegisteredRedirectUri(metadataClient, presented)).toBe(false)
  })
})
