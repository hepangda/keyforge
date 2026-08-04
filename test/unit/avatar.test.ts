import { describe, expect, it } from "vitest"
import {
  AVATAR_UPLOAD_MAX_BODY_BYTES,
  avatarPath,
  avatarUrl,
  generateAvatarKey,
  isAvatarKey,
  MAX_AVATAR_BYTES,
  sniffAvatarType,
  validateAvatarBytes,
} from "../../src/media/avatar"
import { isAvatarUploadPath } from "../../src/media/avatar-http"

function withSignature(signature: readonly number[], length = 64): Uint8Array {
  const bytes = new Uint8Array(length)
  bytes.set(signature)
  return bytes
}

const PNG = withSignature([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const JPEG = withSignature([0xff, 0xd8, 0xff, 0xe0])
const GIF = withSignature([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])

function webp(): Uint8Array {
  const bytes = new Uint8Array(64)
  bytes.set([0x52, 0x49, 0x46, 0x46])
  bytes.set([0x57, 0x45, 0x42, 0x50], 8)
  return bytes
}

describe("sniffAvatarType", () => {
  it("identifies each supported format from its magic bytes", () => {
    expect(sniffAvatarType(PNG)).toBe("image/png")
    expect(sniffAvatarType(JPEG)).toBe("image/jpeg")
    expect(sniffAvatarType(GIF)).toBe("image/gif")
    expect(sniffAvatarType(webp())).toBe("image/webp")
  })

  it("rejects SVG, which would let an uploader serve script from this origin", () => {
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"></svg>')
    expect(sniffAvatarType(svg)).toBeNull()
  })

  it("rejects a RIFF container that is not WebP", () => {
    const wav = new Uint8Array(64)
    wav.set([0x52, 0x49, 0x46, 0x46])
    wav.set([0x57, 0x41, 0x56, 0x45], 8)
    expect(sniffAvatarType(wav)).toBeNull()
  })
})

describe("validateAvatarBytes", () => {
  it("accepts a supported image and reports its sniffed type", () => {
    const result = validateAvatarBytes(PNG)
    expect(result).toMatchObject({ ok: true, contentType: "image/png" })
  })

  it("rejects an empty upload", () => {
    expect(validateAvatarBytes(new Uint8Array(0))).toEqual({ ok: false, reason: "empty" })
  })

  it("rejects an image beyond the size ceiling", () => {
    const large = new Uint8Array(MAX_AVATAR_BYTES + 1)
    large.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    expect(validateAvatarBytes(large)).toEqual({ ok: false, reason: "too_large" })
  })

  it("rejects bytes whose real type is unsupported regardless of any declared type", () => {
    const text = new TextEncoder().encode("not an image at all")
    expect(validateAvatarBytes(text)).toEqual({ ok: false, reason: "unsupported" })
  })
})

describe("upload ceilings", () => {
  it("leaves room for multipart framing above the file limit", () => {
    // A body limit set exactly at MAX_AVATAR_BYTES would reject a file that is
    // itself within the limit, because the multipart envelope adds bytes.
    expect(AVATAR_UPLOAD_MAX_BODY_BYTES).toBeGreaterThan(MAX_AVATAR_BYTES)
  })

  it("accepts an image just under the limit", () => {
    const large = new Uint8Array(MAX_AVATAR_BYTES)
    large.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    expect(validateAvatarBytes(large)).toMatchObject({ ok: true, contentType: "image/png" })
  })
})

describe("avatar keys", () => {
  it("generates unguessable, unique keys with a type-matched extension", () => {
    const first = generateAvatarKey("image/png")
    const second = generateAvatarKey("image/png")
    expect(first).not.toBe(second)
    expect(first.endsWith(".png")).toBe(true)
    expect(isAvatarKey(first)).toBe(true)
    expect(generateAvatarKey("image/jpeg").endsWith(".jpg")).toBe(true)
  })

  it("refuses keys this server could not have generated", () => {
    expect(isAvatarKey("../../etc/passwd")).toBe(false)
    expect(isAvatarKey("short.png")).toBe(false)
    expect(isAvatarKey(`${"a".repeat(43)}.svg`)).toBe(false)
    expect(isAvatarKey(`${"a".repeat(43)}.png`)).toBe(true)
  })

  it("builds same-origin paths and absolute issuer URLs", () => {
    const key = generateAvatarKey("image/webp")
    expect(avatarPath(key)).toBe(`/avatars/${key}`)
    expect(avatarUrl("https://auth.pangda.app", key)).toBe(`https://auth.pangda.app/avatars/${key}`)
  })
})

describe("isAvatarUploadPath", () => {
  it("matches only the endpoints that accept image bytes", () => {
    expect(isAvatarUploadPath("/account/avatar")).toBe(true)
    expect(isAvatarUploadPath("/admin/users/usr_1/avatar")).toBe(true)
    expect(isAvatarUploadPath("/account/avatar/delete")).toBe(false)
    expect(isAvatarUploadPath("/account/profile")).toBe(false)
    expect(isAvatarUploadPath("/admin/users/usr_1/passwords")).toBe(false)
    expect(isAvatarUploadPath("/avatars/abc.png")).toBe(false)
  })
})
