import { randomToken } from "../utils/random"

/**
 * Image types accepted for avatars. SVG is deliberately excluded: it is an
 * active document format and would let an uploader serve script from this
 * origin.
 */
export const ALLOWED_AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"] as const
export type AvatarContentType = (typeof ALLOWED_AVATAR_TYPES)[number]

/**
 * Upper bound on a stored avatar. Workers cannot re-encode, so this is the only
 * size control on the bytes that are ultimately served.
 */
export const MAX_AVATAR_BYTES = 3 * 1024 * 1024

/**
 * Request-body ceiling for avatar uploads. Multipart framing and the CSRF field
 * add a few hundred bytes on top of the file, so a body limit set exactly at
 * `MAX_AVATAR_BYTES` would reject a file that is itself within the limit.
 */
export const AVATAR_UPLOAD_MAX_BODY_BYTES = MAX_AVATAR_BYTES + 64 * 1024

/** Longest edge, in pixels, that clients downscale to before uploading. */
export const AVATAR_TARGET_DIMENSION = 512

const EXTENSIONS: Readonly<Record<AvatarContentType, string>> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
}

function startsWith(bytes: Uint8Array, signature: readonly number[], offset = 0): boolean {
  return signature.every((byte, index) => bytes[offset + index] === byte)
}

/**
 * Identify the real image type from its magic bytes. The client-supplied
 * content type is never trusted, because it decides the type this server later
 * asserts when serving the object back.
 */
export function sniffAvatarType(bytes: Uint8Array): AvatarContentType | null {
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png"
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return "image/jpeg"
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38])) return "image/gif"
  if (
    startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) &&
    startsWith(bytes, [0x57, 0x45, 0x42, 0x50], 8)
  ) {
    return "image/webp"
  }
  return null
}

export type AvatarRejection = "too_large" | "unsupported" | "empty"

export type AvatarValidation =
  | { readonly ok: true; readonly bytes: Uint8Array; readonly contentType: AvatarContentType }
  | { readonly ok: false; readonly reason: AvatarRejection }

/** Validate an upload's size and true type before it reaches storage. */
export function validateAvatarBytes(bytes: Uint8Array): AvatarValidation {
  if (bytes.byteLength === 0) return { ok: false, reason: "empty" }
  if (bytes.byteLength > MAX_AVATAR_BYTES) return { ok: false, reason: "too_large" }
  const contentType = sniffAvatarType(bytes)
  if (contentType === null) return { ok: false, reason: "unsupported" }
  return { ok: true, bytes, contentType }
}

/**
 * Object keys carry 256 bits of entropy and are also the public URL path
 * segment, so the URL itself is the read capability. Keys are not derived from
 * the user id: an avatar URL must not disclose which account it belongs to.
 */
export function generateAvatarKey(contentType: AvatarContentType): string {
  return `${randomToken(32)}.${EXTENSIONS[contentType]}`
}

/** Path of the public endpoint that serves a stored avatar. */
export function avatarPath(key: string): string {
  return `/avatars/${key}`
}

/** Absolute, client-consumable avatar URL for the `picture` claim. */
export function avatarUrl(issuer: string, key: string): string {
  return new URL(avatarPath(key), issuer).toString()
}

/** Reject anything that is not a key this server could itself have generated. */
export function isAvatarKey(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}\.(png|jpg|webp|gif)$/.test(value)
}

export async function putAvatar(
  env: Env,
  key: string,
  bytes: Uint8Array,
  contentType: AvatarContentType,
): Promise<void> {
  await env.AVATARS.put(key, bytes, {
    httpMetadata: { contentType, cacheControl: "public, max-age=31536000, immutable" },
  })
}

export async function getAvatarObject(env: Env, key: string): Promise<R2ObjectBody | null> {
  return isAvatarKey(key) ? await env.AVATARS.get(key) : null
}

/**
 * Best-effort removal of a superseded object. A failure here leaves an orphan
 * that nothing links to, which must never fail the user-facing operation.
 */
export async function deleteAvatarObject(env: Env, key: string | null): Promise<void> {
  if (key === null) return
  try {
    await env.AVATARS.delete(key)
  } catch {
    // Orphaned object; the database no longer references it.
  }
}
