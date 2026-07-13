import type { SessionRecord } from "../types/domain"
import { nowSeconds } from "../utils/time"

export const RECENT_AUTH_SECONDS = 10 * 60

/** True only for a still-current authentication ceremony within ten minutes. */
export function hasRecentAuthentication(
  session: SessionRecord | undefined,
  now = nowSeconds(),
): boolean {
  return (
    session !== undefined &&
    now >= session.authTime &&
    now - session.authTime <= RECENT_AUTH_SECONDS
  )
}
