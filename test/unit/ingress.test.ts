import { describe, expect, it } from "vitest"
import {
  ACCESS_TOKEN_MAX_LENGTH,
  isAccountCapabilityToken,
  isPlausibleCompactJwt,
  isWebAuthnCeremonyId,
} from "../../src/security/ingress"
import { emailCorrelationValue } from "../../src/security/request-meta"

describe("public ingress syntax bounds", () => {
  it("accepts only exact base64url capability lengths", () => {
    expect(isAccountCapabilityToken("a".repeat(43))).toBe(true)
    expect(isAccountCapabilityToken("a".repeat(42))).toBe(false)
    expect(isAccountCapabilityToken(`${"a".repeat(42)}!`)).toBe(false)
    expect(isWebAuthnCeremonyId("a".repeat(22))).toBe(true)
    expect(isWebAuthnCeremonyId("a".repeat(23))).toBe(false)
  })

  it("bounds compact JWT input before key loading", () => {
    expect(isPlausibleCompactJwt("a.b.c")).toBe(true)
    expect(isPlausibleCompactJwt("not-a-jwt")).toBe(false)
    expect(isPlausibleCompactJwt(`a.${"b".repeat(ACCESS_TOKEN_MAX_LENGTH)}.c`)).toBe(false)
  })

  it("collapses oversized email identifiers before correlation hashing", () => {
    expect(emailCorrelationValue("a".repeat(254))).toBe("a".repeat(254))
    expect(emailCorrelationValue("a".repeat(255))).toBe(emailCorrelationValue("b".repeat(4_096)))
  })
})
