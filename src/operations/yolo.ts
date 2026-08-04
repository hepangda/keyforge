/**
 * YOLO mode: a development-only escape hatch that disables every substantive
 * request validation and approves whatever the caller asked for.
 *
 * The switch is deliberately hostile to accidents:
 *
 * - It is only honoured when `ENVIRONMENT` is exactly `dev`. `local`, `test`,
 *   and `production` can never enable it, no matter what `YOLO_MODE` says.
 * - It is only honoured for the exact string `"true"`. Anything else — absent,
 *   empty, `"1"`, `"TRUE"`, whitespace — reads as disabled, so a typo fails
 *   closed rather than silently opening the server.
 * - It is never derived from request data, so a caller cannot turn it on.
 *
 * Every bypass in the codebase routes through {@link isYoloEnabled} so the
 * blast radius is one auditable predicate.
 */

/** Bindings needed to decide whether YOLO mode is active. */
export type YoloEnv = Pick<Env, "ENVIRONMENT"> & { readonly YOLO_MODE?: string }

/** The single environment in which YOLO mode may be enabled. */
export const YOLO_ENVIRONMENT = "dev"

/**
 * True only for a `dev` deployment that explicitly opted in with
 * `YOLO_MODE="true"`. Fails closed everywhere else.
 */
export function isYoloEnabled(env: YoloEnv): boolean {
  return env.ENVIRONMENT === YOLO_ENVIRONMENT && env.YOLO_MODE === "true"
}

/**
 * Log that a validation was skipped. YOLO mode is meant to be loud: a bypass
 * that leaves no trace is indistinguishable from a missing check.
 */
export function noteYoloBypass(check: string, requestId?: string): void {
  console.warn("yolo.bypass", requestId ?? "-", check)
}

/**
 * Return `true` when YOLO mode is on, recording the bypass; otherwise return
 * the result of the real check. Call sites read as
 * `yoloAllow(env, "csrf") || verifyCsrfToken(...)`.
 */
export function yoloAllow(env: YoloEnv, check: string, requestId?: string): boolean {
  if (!isYoloEnabled(env)) return false
  noteYoloBypass(check, requestId)
  return true
}
