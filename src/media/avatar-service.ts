import { clearUserAvatar, setUserAvatar } from "../db/queries/users"
import {
  type AvatarRejection,
  deleteAvatarObject,
  generateAvatarKey,
  MAX_AVATAR_BYTES,
  putAvatar,
  validateAvatarBytes,
} from "./avatar"

export type AvatarStoreResult =
  | { readonly status: "stored"; readonly key: string; readonly contentType: string }
  | { readonly status: "rejected"; readonly reason: AvatarRejection }
  | { readonly status: "not_found" }

/**
 * Validate uploaded bytes and make them the user's avatar.
 *
 * The object is written before the row is updated so a reader never resolves a
 * key whose bytes are missing; the reverse order can only orphan an object,
 * which is invisible to callers.
 */
export async function storeUserAvatar(
  env: Env,
  userId: string,
  bytes: Uint8Array,
): Promise<AvatarStoreResult> {
  const validated = validateAvatarBytes(bytes)
  if (!validated.ok) {
    return { status: "rejected", reason: validated.reason }
  }
  const key = generateAvatarKey(validated.contentType)
  await putAvatar(env, key, validated.bytes, validated.contentType)
  const previousKey = await setUserAvatar(env, userId, { key, contentType: validated.contentType })
  if (previousKey === undefined) {
    await deleteAvatarObject(env, key)
    return { status: "not_found" }
  }
  await deleteAvatarObject(env, previousKey)
  return { status: "stored", key, contentType: validated.contentType }
}

/** Drop a user's avatar and the object behind it. Reports whether one existed. */
export async function removeUserAvatar(env: Env, userId: string): Promise<boolean> {
  const previousKey = await clearUserAvatar(env, userId)
  if (previousKey === undefined || previousKey === null) return false
  await deleteAvatarObject(env, previousKey)
  return true
}

/**
 * Read an uploaded file's bytes, refusing anything over the limit before it is
 * buffered where the declared length allows that decision.
 */
export async function readAvatarUpload(
  value: File | string | null,
): Promise<Uint8Array | AvatarRejection> {
  if (value === null || typeof value === "string") return "empty"
  if (value.size === 0) return "empty"
  if (value.size > MAX_AVATAR_BYTES) return "too_large"
  return new Uint8Array(await value.arrayBuffer())
}
