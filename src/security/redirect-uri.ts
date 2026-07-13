function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"
}

/** OAuth redirect policy: HTTPS, loopback HTTP, or reverse-domain native schemes. */
export function isSafeOAuthRedirectUri(raw: string): boolean {
  try {
    const url = new URL(raw)
    if (url.hash !== "" || url.username !== "" || url.password !== "") return false
    if (url.protocol === "https:") return url.hostname !== ""
    if (url.protocol === "http:") return isLoopback(url.hostname)
    const scheme = url.protocol.slice(0, -1)
    return (
      scheme.includes(".") &&
      /^[a-z][a-z0-9+.-]{2,127}$/i.test(scheme) &&
      !["javascript", "data", "file", "vbscript"].includes(scheme.toLowerCase())
    )
  } catch {
    return false
  }
}

/** Resource indicators are absolute HTTPS URLs or URNs, never browser code. */
export function isSafeResourceUri(raw: string): boolean {
  try {
    const url = new URL(raw)
    if (url.hash !== "" || url.username !== "" || url.password !== "") return false
    return (url.protocol === "https:" && url.hostname !== "") || url.protocol === "urn:"
  } catch {
    return false
  }
}
