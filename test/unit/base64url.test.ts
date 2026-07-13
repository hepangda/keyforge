import { describe, expect, it } from "vitest"
import {
  base64UrlDecode,
  base64UrlDecodeToString,
  base64UrlEncode,
  base64UrlEncodeString,
} from "../../src/utils/base64url"

describe("base64url", () => {
  it("encodes bytes to unpadded url-safe form", () => {
    // Given the ASCII bytes of "Hello"
    const bytes = new Uint8Array([72, 101, 108, 108, 111])
    // When encoded
    const encoded = base64UrlEncode(bytes)
    // Then it matches the known base64url value with no padding
    expect(encoded).toBe("SGVsbG8")
  })

  it("produces only url-safe characters (no +, /, =)", () => {
    // Given bytes that yield '+' and '/' in standard base64
    const bytes = new Uint8Array([251, 255, 191, 250, 254])
    // When encoded
    const encoded = base64UrlEncode(bytes)
    // Then no standard-base64-only characters appear
    expect(encoded).not.toMatch(/[+/=]/)
  })

  it("round-trips arbitrary bytes", () => {
    // Given 256 distinct byte values
    const bytes = new Uint8Array(256)
    for (let i = 0; i < 256; i += 1) {
      bytes[i] = i
    }
    // When encoded then decoded
    const decoded = base64UrlDecode(base64UrlEncode(bytes))
    // Then the bytes are unchanged
    expect([...decoded]).toEqual([...bytes])
  })

  it("decodes input regardless of missing padding", () => {
    // Given the same value with and without padding characters
    // When both are decoded
    // Then they yield identical bytes
    expect([...base64UrlDecode("SGVsbG8")]).toEqual([...base64UrlDecode("SGVsbG8=")])
  })

  it("round-trips strings", () => {
    // Given a UTF-8 string with multibyte characters
    const value = "keyforge 🔐 認証"
    // When encoded then decoded as a string
    // Then it is preserved
    expect(base64UrlDecodeToString(base64UrlEncodeString(value))).toBe(value)
  })
})
