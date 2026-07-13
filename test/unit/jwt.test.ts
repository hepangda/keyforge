import { env } from "cloudflare:test"
import { decodeProtectedHeader } from "jose"
import { describe, expect, it } from "vitest"
import { signJwt, verifyAccessToken, verifyJwt } from "../../src/tokens/jwt"
import { getPublicJwks } from "../../src/tokens/key-rotation"

describe("jwt RS256 sign/verify", () => {
  it("signs and verifies a token, setting iat/exp", async () => {
    // Given claims for an access token
    const token = await signJwt(
      env,
      { iss: env.ISSUER, sub: "usr_test", aud: "https://api.pangda.app" },
      { typ: "at+jwt", expiresInSeconds: 900 },
    )
    // When verified with the expected audience
    const payload = await verifyJwt(env, token, { audience: "https://api.pangda.app" })
    // Then the claims round-trip and lifetimes are populated
    expect(payload.sub).toBe("usr_test")
    expect(payload.iss).toBe(env.ISSUER)
    expect(typeof payload.iat).toBe("number")
    expect(typeof payload.exp).toBe("number")
  })

  it("signs with a kid published in the JWKS as an RS256 signing key", async () => {
    // Given a freshly signed token
    const token = await signJwt(
      env,
      { iss: env.ISSUER, sub: "usr_test", aud: "x" },
      { typ: "JWT", expiresInSeconds: 60 },
    )
    // When inspecting its header against the JWKS
    const header = decodeProtectedHeader(token)
    const jwks = await getPublicJwks(env)
    const match = jwks.keys.find((key) => key.kid === header.kid)
    // Then the key is present and marked for RS256 signing
    expect(header.alg).toBe("RS256")
    expect(match).toBeDefined()
    expect(match?.use).toBe("sig")
    expect(match?.alg).toBe("RS256")
  })

  it("rejects a tampered token", async () => {
    // Given a valid token whose signature is corrupted
    const token = await signJwt(
      env,
      { iss: env.ISSUER, sub: "usr_test", aud: "x" },
      { typ: "JWT", expiresInSeconds: 60 },
    )
    const tampered = `${token.slice(0, -3)}xyz`
    // When verifying — Then it throws
    await expect(verifyJwt(env, tampered)).rejects.toThrow()
  })

  it("rejects an audience mismatch", async () => {
    // Given a token for the API audience
    const token = await signJwt(
      env,
      { iss: env.ISSUER, sub: "usr_test", aud: "https://api.pangda.app" },
      { typ: "at+jwt", expiresInSeconds: 60 },
    )
    // When verified against a different audience — Then it throws
    await expect(verifyJwt(env, token, { audience: "https://other.example" })).rejects.toThrow()
  })

  it("verifies an access token only when type, use, and audience all match", async () => {
    const token = await signJwt(
      env,
      {
        iss: env.ISSUER,
        sub: "usr_test",
        aud: "https://api.pangda.app",
        client_id: "pangda_app",
        scope: "openid",
        token_use: "access_token",
      },
      { typ: "at+jwt", expiresInSeconds: 60 },
    )
    await expect(
      verifyAccessToken(env, token, { audience: "https://api.pangda.app", actor: "user" }),
    ).resolves.toMatchObject({ sub: "usr_test", token_use: "access_token" })
  })

  it("rejects a signed ID token through the dedicated access-token verifier", async () => {
    const idToken = await signJwt(
      env,
      { iss: env.ISSUER, sub: "usr_test", aud: "pangda_app" },
      { typ: "JWT", expiresInSeconds: 60 },
    )
    await expect(verifyAccessToken(env, idToken, { audience: "pangda_app" })).rejects.toThrow()
  })

  it("rejects an at+jwt without the access-token use claim", async () => {
    const token = await signJwt(
      env,
      {
        iss: env.ISSUER,
        sub: "usr_test",
        aud: "https://api.pangda.app",
        client_id: "pangda_app",
        scope: "openid",
      },
      { typ: "at+jwt", expiresInSeconds: 60 },
    )
    await expect(verifyAccessToken(env, token)).rejects.toThrow("token_use")
  })
})
