import { Hono } from "hono"
import { getAvatarObject } from "../media/avatar"
import type { AppBindings } from "../types/app"

export const avatars = new Hono<AppBindings>()

/**
 * Serve an uploaded avatar. The 256-bit object key in the path is the read
 * capability, so this endpoint is unauthenticated by design: relying parties
 * receive the URL in the `picture` claim and render it directly from a browser
 * that holds no KeyForge credentials. Keys change whenever the image changes,
 * which is what makes the immutable cache safe.
 */
avatars.get("/avatars/:key", async (c) => {
  const object = await getAvatarObject(c.env, c.req.param("key"))
  if (object === null) {
    return c.json({ error: "not_found" }, 404)
  }

  const etag = object.httpEtag
  if (c.req.header("if-none-match") === etag) {
    return new Response(null, { status: 304, headers: { etag, ...avatarCacheHeaders() } })
  }

  return new Response(object.body, {
    headers: {
      etag,
      "content-type": object.httpMetadata?.contentType ?? "application/octet-stream",
      "content-length": String(object.size),
      // Never let a stored image be interpreted as an active document.
      "content-disposition": "inline",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; sandbox",
      ...avatarCacheHeaders(),
    },
  })
})

function avatarCacheHeaders(): Record<string, string> {
  return { "cache-control": "public, max-age=31536000, immutable" }
}
