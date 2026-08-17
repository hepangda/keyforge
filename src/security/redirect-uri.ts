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

/** Resource indicators are HTTPS URLs, loopback HTTP for development, or URNs. */
export function isSafeResourceUri(raw: string): boolean {
  try {
    const url = new URL(raw)
    if (url.hash !== "" || url.username !== "" || url.password !== "") return false
    return (
      (url.protocol === "https:" && url.hostname !== "") ||
      (url.protocol === "http:" && isLoopback(url.hostname)) ||
      url.protocol === "urn:"
    )
  } catch {
    return false
  }
}

/** Remote MCP transport identity: an unambiguous HTTPS URL or loopback HTTP URL. */
export function isSafeMcpResourceUri(raw: string): boolean {
  if (!isSafeResourceUri(raw)) return false
  const url = new URL(raw)
  return (
    url.search === "" &&
    (url.protocol === "https:" || (url.protocol === "http:" && isLoopback(url.hostname)))
  )
}

/** Loopback MCP resources are executable only in the local Worker profile. */
export function isMcpResourceUriAllowed(environment: string | undefined, raw: string): boolean {
  if (!isSafeMcpResourceUri(raw)) return false
  return new URL(raw).protocol === "https:" || environment === "local"
}
