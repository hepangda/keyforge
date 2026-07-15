import { ulid } from "ulidx"

/**
 * Resource-prefixed identifier scheme (`usr_01H...`). The prefix is a
 * human-readable type tag; the body is a ULID (lexicographically sortable,
 * time-ordered, CSPRNG-backed via ulidx).
 */
export const ID_PREFIX = {
  user: "usr",
  password: "pwd",
  session: "sess",
  group: "grp",
  consent: "cnst",
  accessToken: "atk",
  refreshTokenFamily: "rtf",
  authGrant: "grant",
  device: "dev",
  webauthn: "wac",
  audit: "log",
  resource: "res",
  emailVerification: "evt",
  passwordReset: "prt",
} as const

export type IdPrefix = (typeof ID_PREFIX)[keyof typeof ID_PREFIX]

/** Generate a prefixed ULID, e.g. `usr_01J9Z...`. */
export function generateId(prefix: IdPrefix): string {
  return `${prefix}_${ulid()}`
}
