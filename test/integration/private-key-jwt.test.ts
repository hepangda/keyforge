import { env } from "cloudflare:test"
import { exportJWK, generateKeyPair, SignJWT } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { createResource } from "../../src/db/queries/resources"
import { resolveAuthorizationClient } from "../../src/oauth/client-id-metadata"
import { PrivateKeyJwtError, verifyPrivateKeyJwt } from "../../src/oauth/private-key-jwt"

const CLIENT_ID = "https://signed-client.example.com/oauth/client.json"
const JWKS_URI = "https://signed-client.example.com/oauth/jwks.json"
const REDIRECT_URI = "https://signed-client.example.com/oauth/callback"
const RESOURCE = "https://signed-mcp.example.com/mcp"
const TOKEN_ENDPOINT = "https://auth.pangda.app/oauth/token"

beforeEach(async () => {
  await env.DB.prepare("DELETE FROM oauth_clients WHERE client_id = ?").bind(CLIENT_ID).run()
  await env.DB.prepare("DELETE FROM oauth_resources WHERE resource_uri = ?").bind(RESOURCE).run()
  await createResource(env, {
    resourceUri: RESOURCE,
    name: "Signed MCP",
    allowedScopes: ["mcp.tools.read"],
    mcpEnabled: true,
    metadataClientPolicy: "consent_required",
  })
})

describe("private_key_jwt metadata clients", () => {
  it("verifies a bounded client assertion and rejects replay", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true })
    const publicJwk = await exportJWK(publicKey)
    const jwks = { keys: [{ ...publicJwk, kid: "signing-key", use: "sig", alg: "RS256" }] }
    const client = await resolveAuthorizationClient(env, CLIENT_ID, RESOURCE, {
      resolveHost: async () => ["1.1.1.1"],
      fetcher: async () =>
        Response.json({
          client_id: CLIENT_ID,
          client_name: "Signed MCP Client",
          redirect_uris: [REDIRECT_URI],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_methods_supported: ["private_key_jwt"],
          token_endpoint_auth_method: "private_key_jwt",
          jwks_uri: JWKS_URI,
        }),
    })
    expect(client).toMatchObject({
      type: "confidential",
      tokenEndpointAuthMethods: ["private_key_jwt"],
      metadataJwksUri: JWKS_URI,
    })
    if (client === null) throw new Error("metadata client was not resolved")

    const now = Math.floor(Date.now() / 1000)
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "signing-key" })
      .setIssuer(CLIENT_ID)
      .setSubject(CLIENT_ID)
      .setAudience(TOKEN_ENDPOINT)
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .setJti("single-use-assertion")
      .sign(privateKey)
    const dependencies = {
      resolveHost: async () => ["1.1.1.1"],
      fetcher: async () => Response.json(jwks),
    }

    await expect(
      verifyPrivateKeyJwt(env, client, assertion, TOKEN_ENDPOINT, dependencies),
    ).resolves.toBeUndefined()
    await expect(
      verifyPrivateKeyJwt(env, client, assertion, TOKEN_ENDPOINT, dependencies),
    ).rejects.toThrow("already used")

    const wrongAudience = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "signing-key" })
      .setIssuer(CLIENT_ID)
      .setSubject(CLIENT_ID)
      .setAudience("https://attacker.example.com/token")
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .setJti("wrong-audience")
      .sign(privateKey)
    await expect(
      verifyPrivateKeyJwt(env, client, wrongAudience, TOKEN_ENDPOINT, dependencies),
    ).rejects.toBeInstanceOf(PrivateKeyJwtError)
  })
})
