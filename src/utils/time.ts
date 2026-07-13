/** Current time as UNIX seconds (JWT `iat`/`exp` unit). */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/** Current time in milliseconds. */
export function nowMs(): number {
  return Date.now()
}

/** Seconds until `expiresAtSeconds`, clamped at 0. */
export function secondsUntil(expiresAtSeconds: number): number {
  return Math.max(0, expiresAtSeconds - nowSeconds())
}

/** Whether an absolute UNIX-seconds expiry is in the past. */
export function isExpired(expiresAtSeconds: number): boolean {
  return nowSeconds() >= expiresAtSeconds
}
