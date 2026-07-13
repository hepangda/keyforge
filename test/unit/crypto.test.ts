import { describe, expect, it } from "vitest"
import {
  hashPassword,
  sha256Hex,
  timingSafeEqualString,
  verifyPassword,
} from "../../src/security/crypto"

describe("sha256Hex", () => {
  it("matches the NIST 'abc' test vector", async () => {
    // Given the input "abc"
    // When hashed
    // Then it equals the known SHA-256 digest
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
  })
})

describe("timingSafeEqualString", () => {
  it("is true for equal strings and false otherwise", () => {
    expect(timingSafeEqualString("abcdef", "abcdef")).toBe(true)
    expect(timingSafeEqualString("abcdef", "abcdeg")).toBe(false)
    expect(timingSafeEqualString("abc", "abcd")).toBe(false)
  })
})

describe("password hashing", () => {
  it("round-trips a correct password", async () => {
    // Given a hashed password
    const stored = await hashPassword("correct horse battery staple")
    // When verifying the same password
    // Then it succeeds
    expect(await verifyPassword("correct horse battery staple", stored)).toBe(true)
  })

  it("rejects an incorrect password", async () => {
    // Given a hashed password
    const stored = await hashPassword("correct horse battery staple")
    // When verifying a different password
    // Then it fails
    expect(await verifyPassword("Correct Horse Battery Staple", stored)).toBe(false)
  })

  it("produces a self-describing scrypt string with a unique salt", async () => {
    // Given two hashes of the same password
    const a = await hashPassword("same-password")
    const b = await hashPassword("same-password")
    // Then each is scrypt-tagged and they differ (random salt)
    expect(a.startsWith("scrypt$")).toBe(true)
    expect(a).not.toBe(b)
  })

  it("rejects a malformed stored hash", async () => {
    // Given a stored value that is not a valid scrypt string
    // When verifying
    // Then it fails closed rather than throwing
    expect(await verifyPassword("whatever", "not-a-valid-hash")).toBe(false)
  })
})
