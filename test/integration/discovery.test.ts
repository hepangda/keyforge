import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import type { DiscoveryMetadata } from "../../src/oidc/discovery"
import { buildDiscoveryMetadata } from "../../src/oidc/discovery"

const ISSUER = "https://auth.pangda.app"

describe("GET /.well-known/openid-configuration", () => {
  it("returns the discovery document matching the issuer", async () => {
    // Given the running worker
    // When fetching the discovery endpoint
    const res = await SELF.fetch(`${ISSUER}/.well-known/openid-configuration`)
    // Then it is 200 JSON matching the builder output
    expect(res.status).toBe(200)
    const body = await res.json<DiscoveryMetadata>()
    expect(body).toEqual(buildDiscoveryMetadata(ISSUER))
  })

  it("advertises the required grants and PKCE S256", async () => {
    const res = await SELF.fetch(`${ISSUER}/.well-known/openid-configuration`)
    const body = await res.json<DiscoveryMetadata>()
    // Then device_code and client_credentials are supported, implicit is not
    expect(body.grant_types_supported).toContain("authorization_code")
    expect(body.grant_types_supported).toContain("refresh_token")
    expect(body.grant_types_supported).toContain("urn:ietf:params:oauth:grant-type:device_code")
    expect(body.grant_types_supported).toContain("client_credentials")
    expect(body.grant_types_supported).not.toContain("implicit")
    expect(body.grant_types_supported).not.toContain("password")
    expect(body.code_challenge_methods_supported).toEqual(["S256"])
    expect(body.end_session_endpoint).toBe(`${ISSUER}/oauth/end_session`)
    expect(body.prompt_values_supported).toEqual(["none", "login", "consent"])
    expect(body.id_token_signing_alg_values_supported).toEqual(["RS256"])
    expect(body.scopes_supported).toContain("groups")
    expect(body.claims_supported).toContain("groups")
    expect(body.claims_supported).toContain("user_type")
  })
})

describe("GET /.well-known/jwks.json", () => {
  it("returns at least one RSA signing key", async () => {
    const res = await SELF.fetch(`${ISSUER}/.well-known/jwks.json`)
    expect(res.status).toBe(200)
    const jwks = await res.json<{ keys: Array<Record<string, unknown>> }>()
    expect(jwks.keys.length).toBeGreaterThanOrEqual(1)
    const first = jwks.keys[0]
    expect(first?.["kty"]).toBe("RSA")
    expect(first?.["use"]).toBe("sig")
    expect(first?.["alg"]).toBe("RS256")
    expect(typeof first?.["kid"]).toBe("string")
    // Private material must never be published
    expect(first?.["d"]).toBeUndefined()
  })
})

describe("health", () => {
  it("reports liveness", async () => {
    const res = await SELF.fetch(`${ISSUER}/health`)
    expect(res.status).toBe(200)
    const body = await res.json<{ status: string }>()
    expect(body.status).toBe("ok")
  })

  it("reports readiness once D1 is reachable", async () => {
    const res = await SELF.fetch(`${ISSUER}/health/ready`)
    expect(res.status).toBe(200)
    const body = await res.json<{
      status: string
      checks: Record<string, { status: string }>
    }>()
    expect(body.status).toBe("ready")
    expect(body.checks).toEqual({
      bindings: { status: "ok" },
      runtime_configuration: { status: "ok" },
      database: { status: "ok" },
      signing_keys: { status: "ok" },
      audit_queue: { status: "ok" },
      email_queue: { status: "ok" },
      durable_objects: { status: "ok" },
    })
  })
})
