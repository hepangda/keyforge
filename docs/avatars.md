# Avatars

Users can upload a profile photo. It is stored in R2 and surfaced to relying
parties through the standard OIDC `picture` claim.

## Model

`users.picture` keeps its original meaning: an externally hosted image URL.
An uploaded avatar is stored separately (`avatar_key`, `avatar_content_type`,
`avatar_updated_at`) and takes precedence, because it is the value the user
last chose here.

`avatar_key` is a 256-bit random object key that is also the public URL path
segment. Replacing or removing an avatar issues a new key, so the previous URL
stops resolving and the immutable cache never serves a stale image.

## Reading

`GET /avatars/:key` serves the image with no credentials. Possession of the
unguessable URL is the read capability, which is what lets a relying party put
the `picture` claim straight into an `<img>` tag from a browser holding no
KeyForge session. Responses are `public, max-age=31536000, immutable`, support
`if-none-match`, and are served with `nosniff` plus a sandboxing CSP so a
stored file can never be interpreted as an active document.

Keys are not derived from the user id, so an avatar URL does not disclose which
account it belongs to. The bucket itself is never exposed through a public R2
domain.

`picture` appears in ID Tokens and `/oauth/userinfo` only under the `profile`
scope, exactly as before.

## Writing

- `POST /account/avatar` — multipart self-service upload (session + CSRF,
  10 uploads per hour per user/IP).
- `POST /account/avatar/delete` — self-service removal.
- `PUT /admin/users/:id/avatar` and `DELETE /admin/users/:id/avatar` — see
  `docs/admin-api.md`.

PNG, JPEG, WebP, and GIF are accepted up to **3 MB**. The type is decided by
sniffing magic bytes, never by the client's `content-type`. SVG is rejected
outright: it is an active document format and would let an uploader serve
script from this origin.

The avatar endpoints carry their own request-body ceiling
(`AVATAR_UPLOAD_MAX_BODY_BYTES`, the file limit plus multipart framing room);
every other route keeps the global 256 KB limit.

### Cropping and browser-side resizing

`/assets/avatar.js` uploads in-page rather than navigating. Choosing a file
opens a cropper showing the whole photo with a square selection over it — drag
inside the square to move it, drag a corner to resize, or drag on empty space to
draw a new one. The area outside the selection is dimmed and a circle is drawn
inside it, since the avatar is rendered round everywhere else.

The selection is kept square (a corner resize takes the larger of the two axis
deltas) and clamped inside the image; arrow keys move it and `+`/`-` resize it,
so the cropper works without a pointer. "Reset selection" restores the largest
centred square.

On submit the selected square is redrawn at up to 512 px (never upscaled beyond
the pixels the source actually has, and re-clamped to the source bounds so
rounding cannot produce an out-of-bounds read), re-encoded to WebP — JPEG where WebP
encoding is unavailable — and posted with `accept: application/json`, showing
progress and a specific, localized error in the form.

That canvas round-trip is also the only sanitization the system performs. Workers
cannot re-encode images, so a canvas pass is what discards EXIF and any bytes
appended after the image data. It is best-effort by nature — it is client-side, and the
original file is uploaded if canvas rendering is unavailable — so the server still
relies on the type whitelist, the size ceiling, the fixed response
`content-type`, `nosniff`, and the sandbox CSP to contain a hostile file.

### Response shape

The routes answer in whichever form the caller asked for. With
`accept: application/json` they return `{ ok: true, outcome, picture_url }` or
`{ ok: false, error, max_bytes }` with a matching status (413 too large, 415
unsupported, 429 rate limited). A plain form post — a browser with JavaScript
disabled — still gets a 302 back to the dashboard carrying a notice, so no user
ever sees a bare JSON error page.

## Storage

Bucket binding `AVATARS` (`keyforge-avatars-local` / `-dev` / `keyforge-avatars`).
Objects are written before the database row is updated, so a resolvable key
always has bytes behind it; the failure mode is an orphaned object that nothing
references. Superseded objects are deleted best-effort — a failed delete never
fails the user's request.
