import type { Context } from "hono"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { AppBindings } from "../types/app"
import { MAX_AVATAR_BYTES } from "./avatar"

/**
 * Whether a path accepts image bytes and therefore needs the larger request
 * ceiling. Matched here rather than by route registration because the body
 * limit must be chosen before routing.
 */
export function isAvatarUploadPath(pathname: string): boolean {
  return pathname === "/account/avatar" || /^\/admin\/users\/[^/]+\/avatar$/.test(pathname)
}

/** Every outcome an avatar mutation can report to a client. */
export type AvatarOutcome =
  | "avatar_updated"
  | "avatar_removed"
  | "avatar_too_large"
  | "avatar_unsupported"
  | "avatar_missing"
  | "avatar_rate_limited"
  | "invalid"
  | "not_found"

const SUCCESS_OUTCOMES = new Set<AvatarOutcome>(["avatar_updated", "avatar_removed"])

const STATUS: Readonly<Record<AvatarOutcome, ContentfulStatusCode>> = {
  avatar_updated: 200,
  avatar_removed: 200,
  avatar_too_large: 413,
  avatar_unsupported: 415,
  avatar_missing: 400,
  avatar_rate_limited: 429,
  invalid: 403,
  not_found: 404,
}

/**
 * Whether the caller is the in-page uploader rather than a plain form post.
 * The uploader asks for JSON explicitly, so a browser without JavaScript keeps
 * the redirect-and-render behaviour and never sees a raw JSON body.
 */
export function wantsJsonAvatarResponse(c: Context<AppBindings>): boolean {
  return c.req.header("accept")?.includes("application/json") === true
}

/**
 * Answer an avatar mutation in whichever form the caller asked for: JSON for
 * the asynchronous uploader, a redirect carrying a notice for a plain form.
 */
export function avatarResponse(
  c: Context<AppBindings>,
  outcome: AvatarOutcome,
  redirectTo: string,
  extra: Readonly<Record<string, unknown>> = {},
): Response {
  if (!wantsJsonAvatarResponse(c)) {
    return c.redirect(redirectTo)
  }
  const status = STATUS[outcome]
  if (SUCCESS_OUTCOMES.has(outcome)) {
    return c.json({ ok: true, outcome, ...extra }, 200)
  }
  return c.json({ ok: false, error: outcome, max_bytes: MAX_AVATAR_BYTES, ...extra }, status)
}

/**
 * Reject an upload whose body exceeded the transport ceiling. This runs before
 * session and i18n middleware, so it cannot render a localized page; the
 * uploader turns the machine-readable error into a localized message, and a
 * no-JavaScript form lands on the dashboard notice instead.
 */
export function avatarTooLargeResponse(c: Context<AppBindings>): Response {
  const accept = c.req.header("accept") ?? ""
  if (accept.includes("text/html") && new URL(c.req.url).pathname.startsWith("/account/")) {
    return c.redirect("/?section=profile&flow=edit-profile&notice=avatar_too_large", 303)
  }
  return c.json({ ok: false, error: "avatar_too_large", max_bytes: MAX_AVATAR_BYTES }, 413)
}
