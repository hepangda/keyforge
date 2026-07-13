import { describe, expect, it } from "vitest"
import { computeS256Challenge, isValidCodeVerifier, verifyPkce } from "../../src/oauth/pkce"

// RFC 7636 Appendix B reference vector.
const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

describe("pkce S256", () => {
  it("computes the RFC 7636 reference challenge", async () => {
    // Given the RFC reference verifier
    // When computing its S256 challenge
    const challenge = await computeS256Challenge(RFC_VERIFIER)
    // Then it matches the published value
    expect(challenge).toBe(RFC_CHALLENGE)
  })

  it("verifies a matching verifier/challenge pair", async () => {
    // Given the RFC reference pair
    // When verifying
    // Then it succeeds
    expect(await verifyPkce(RFC_VERIFIER, RFC_CHALLENGE)).toBe(true)
  })

  it("rejects a non-matching verifier", async () => {
    // Given a wrong verifier of valid length
    const wrong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    // When verifying against the RFC challenge
    // Then it fails
    expect(await verifyPkce(wrong, RFC_CHALLENGE)).toBe(false)
  })

  it("rejects a syntactically invalid verifier without hashing", async () => {
    // Given a too-short verifier
    const tooShort = "short"
    // When validating and verifying
    // Then both reject it
    expect(isValidCodeVerifier(tooShort)).toBe(false)
    expect(await verifyPkce(tooShort, RFC_CHALLENGE)).toBe(false)
  })

  it("accepts verifiers within the 43-128 length bounds", () => {
    // Given verifiers at the boundaries
    // When validating
    // Then the in-range ones pass and the out-of-range one fails
    expect(isValidCodeVerifier("a".repeat(43))).toBe(true)
    expect(isValidCodeVerifier("a".repeat(128))).toBe(true)
    expect(isValidCodeVerifier("a".repeat(129))).toBe(false)
    expect(isValidCodeVerifier("a".repeat(42))).toBe(false)
  })
})
