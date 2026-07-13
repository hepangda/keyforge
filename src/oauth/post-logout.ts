/**
 * Logout redirects are browser navigation targets. Permit HTTPS everywhere
 * and HTTP only for loopback development; reject credentials and fragments.
 */
export function isSafePostLogoutRedirectUri(value: string): boolean {
  try {
    const url = new URL(value)
    if (url.username !== "" || url.password !== "" || url.hash !== "") {
      return false
    }
    if (url.protocol === "https:") {
      return true
    }
    return (
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
    )
  } catch {
    return false
  }
}
