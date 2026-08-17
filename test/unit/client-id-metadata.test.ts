import { describe, expect, it, vi } from "vitest"
import {
  ClientIdMetadataError,
  fetchClientIdMetadata,
  isPublicInternetAddress,
} from "../../src/oauth/client-id-metadata"
import { isValidOAuthClientId, parseClientIdentifierUrl } from "../../src/oauth/client-identifier"

const CLIENT_ID = "https://client.example.com/oauth/client.json"
const REDIRECT_URI = "https://client.example.com/oauth/callback"

function metadata(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: CLIENT_ID,
    client_name: "Example MCP Client",
    redirect_uris: [REDIRECT_URI],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...overrides,
  }
}

function jsonDocument(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set("content-type", "application/json")
  return new Response(JSON.stringify(body), { ...init, headers })
}

describe("Client Identifier URLs", () => {
  it("accepts a strict HTTPS document URL alongside static client IDs", () => {
    expect(parseClientIdentifierUrl(CLIENT_ID)?.href).toBe(CLIENT_ID)
    expect(isValidOAuthClientId(CLIENT_ID)).toBe(true)
    expect(isValidOAuthClientId("static_client-1")).toBe(true)
  })

  it.each([
    "http://client.example.com/oauth/client.json",
    "https://client.example.com/",
    "https://user@client.example.com/oauth/client.json",
    "https://client.example.com/oauth/client.json?version=1",
    "https://client.example.com/oauth/%2e%2e/secret.json",
  ])("rejects unsafe or ambiguous identifier %s", (candidate) => {
    expect(parseClientIdentifierUrl(candidate)).toBeNull()
  })
})

describe("metadata fetch SSRF policy", () => {
  it.each([
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
  ])("recognizes public address %s", (address) =>
    expect(isPublicInternetAddress(address)).toBe(true))

  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "203.0.113.10",
    "::1",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
  ])("rejects special-use address %s", (address) => {
    expect(isPublicInternetAddress(address)).toBe(false)
  })

  it("blocks a special-use DNS result before fetching metadata", async () => {
    const fetcher = vi.fn<typeof fetch>()
    await expect(
      fetchClientIdMetadata(CLIENT_ID, {
        fetcher,
        resolveHost: async () => ["169.254.169.254"],
      }),
    ).rejects.toThrow(ClientIdMetadataError)
    expect(fetcher).not.toHaveBeenCalled()
  })
})

describe("fetchClientIdMetadata", () => {
  it("accepts a public no-secret authorization-code client and respects bounded cache TTL", async () => {
    const before = Math.floor(Date.now() / 1000)
    const fetcher: typeof fetch = async (input, init) => {
      expect(String(input)).toBe(CLIENT_ID)
      expect(init?.method).toBe("GET")
      expect(init?.redirect).toBe("manual")
      expect(init?.cache).toBe("no-store")
      expect(init?.signal).toBeInstanceOf(AbortSignal)
      return jsonDocument(metadata(), { headers: { "cache-control": "public, max-age=120" } })
    }

    const result = await fetchClientIdMetadata(CLIENT_ID, {
      fetcher,
      resolveHost: async () => ["1.1.1.1", "2606:4700:4700::1111"],
    })
    expect(result).toMatchObject({
      clientId: CLIENT_ID,
      clientName: "Example MCP Client",
      redirectUris: [REDIRECT_URI],
      allowedGrantTypes: ["authorization_code", "refresh_token"],
    })
    expect(result.expiresAt).toBeGreaterThanOrEqual(before + 120)
    expect(result.expiresAt).toBeLessThanOrEqual(before + 121)
  })

  it.each([
    metadata({ client_id: "https://attacker.example.com/oauth/client.json" }),
    metadata({ client_secret: "must-not-be-here" }),
    metadata({ token_endpoint_auth_method: "client_secret_post" }),
    metadata({ response_types: ["code", "token"] }),
    metadata({ grant_types: ["authorization_code", "client_credentials"] }),
    metadata({ redirect_uris: ["https://user@client.example.com/callback"] }),
  ])("rejects mismatched, secret-bearing, or unsupported metadata", async (document) => {
    await expect(
      fetchClientIdMetadata(CLIENT_ID, {
        fetcher: async () => jsonDocument(document),
        resolveHost: async () => ["1.1.1.1"],
      }),
    ).rejects.toThrow(ClientIdMetadataError)
  })

  it("follows only bounded public HTTPS redirects and bounds the response", async () => {
    const fetcher = vi.fn<typeof fetch>(async (input) =>
      String(input) === CLIENT_ID
        ? new Response(null, {
            status: 302,
            headers: { location: "https://cdn.example.com/client.json" },
          })
        : jsonDocument(metadata()),
    )
    await expect(
      fetchClientIdMetadata(CLIENT_ID, {
        fetcher,
        resolveHost: async () => ["1.1.1.1"],
      }),
    ).resolves.toMatchObject({ clientId: CLIENT_ID })
    expect(fetcher).toHaveBeenCalledTimes(2)

    await expect(
      fetchClientIdMetadata(CLIENT_ID, {
        fetcher: async () =>
          new Response("{}", {
            headers: {
              "content-length": String(5 * 1024 + 1),
              "content-type": "application/json",
            },
          }),
        resolveHost: async () => ["1.1.1.1"],
      }),
    ).rejects.toThrow("too large")
  })

  it("does not cache metadata responses that require revalidation", async () => {
    const result = await fetchClientIdMetadata(CLIENT_ID, {
      fetcher: async () =>
        jsonDocument(metadata(), {
          headers: { "cache-control": 'public, max-age=3600, no-cache="client_id"' },
        }),
      resolveHost: async () => ["1.1.1.1"],
    })
    expect(result.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))
  })
})
