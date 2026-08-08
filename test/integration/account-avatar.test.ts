import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { createSession } from "../../src/auth/session"
import { createUser, getUserById } from "../../src/db/queries/users"
import { MAX_AVATAR_BYTES } from "../../src/media/avatar"
import { buildUserClaims } from "../../src/oidc/claims"

const ISSUER = "https://auth.pangda.app"

let adminCookie = ""
let userCookie = ""
let userId = ""

function pngBytes(size = 128): Uint8Array {
  const bytes = new Uint8Array(size)
  bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
  bytes[20] = 0x42
  return bytes
}

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
  ])
  const admin = await createUser(env, { email: "avatar-admin@pangda.app", name: "Admin" })
  await env.DB.prepare(
    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_admins', unixepoch())",
  )
    .bind(admin.id)
    .run()
  adminCookie = `__Host-keyforge_session=${(await createSession(env, { userId: admin.id, authMethod: "password", ttlSeconds: 3600 })).token}`

  const user = await createUser(env, { email: "avatar-user@pangda.app", name: "Avatar User" })
  userId = user.id
  userCookie = `__Host-keyforge_session=${(await createSession(env, { userId: user.id, authMethod: "password", ttlSeconds: 3600 })).token}`
})

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

async function freshCsrf(): Promise<string> {
  const res = await SELF.fetch(`${ISSUER}/`, { headers: { cookie: userCookie } })
  return cookieValue(res.headers.getSetCookie(), "__Host-keyforge_csrf")
}

async function uploadAvatar(
  bytes: Uint8Array,
  filename = "avatar.png",
  accept?: string,
): Promise<Response> {
  const csrf = await freshCsrf()
  const form = new FormData()
  form.set("csrf_token", csrf)
  form.set("avatar", new File([bytes], filename, { type: "image/png" }))
  return SELF.fetch(`${ISSUER}/account/avatar`, {
    method: "POST",
    headers: {
      cookie: `${userCookie}; __Host-keyforge_csrf=${csrf}`,
      origin: ISSUER,
      ...(accept === undefined ? {} : { accept }),
    },
    body: form,
    redirect: "manual",
  })
}

function adminRequest(method: string, path: string, body?: BodyInit): Promise<Response> {
  return SELF.fetch(`${ISSUER}${path}`, {
    method,
    headers: {
      cookie: adminCookie,
      origin: ISSUER,
      "sec-fetch-site": "same-origin",
      ...(body === undefined ? {} : { "content-type": "image/png" }),
    },
    ...(body === undefined ? {} : { body }),
    redirect: "manual",
  })
}

describe("account avatar upload", () => {
  it("renders the crop viewport and its controls in the edit-profile flow", async () => {
    const page = await SELF.fetch(`${ISSUER}/?section=profile&flow=edit-profile`, {
      headers: { cookie: userCookie },
    })
    const html = await page.text()
    expect(html).toContain("data-avatar-cropper")
    expect(html).toContain("data-avatar-canvas")
    expect(html).toContain("data-avatar-reset")
    expect(html).toContain("data-avatar-cancel")
    expect(html).toContain("/assets/avatar.js")
  })

  it("stores an uploaded image and links it from the dashboard", async () => {
    const res = await uploadAvatar(pngBytes())
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("notice=avatar_updated")

    const user = await getUserById(env, userId)
    expect(user?.avatarKey).not.toBeNull()
    expect(user?.avatarContentType).toBe("image/png")

    const page = await SELF.fetch(`${ISSUER}/?section=profile&flow=edit-profile`, {
      headers: { cookie: userCookie },
    })
    expect(await page.text()).toContain(`/avatars/${user?.avatarKey}`)
  })

  it("rejects an upload whose bytes are not a supported image", async () => {
    const res = await uploadAvatar(new TextEncoder().encode("<svg></svg>"), "x.svg")
    expect(res.headers.get("location")).toContain("notice=avatar_unsupported")
    expect((await getUserById(env, userId))?.avatarKey).toBeNull()
  })

  it("rejects an upload without a valid CSRF token", async () => {
    const form = new FormData()
    form.set("csrf_token", "forged")
    form.set("avatar", new File([pngBytes()], "a.png", { type: "image/png" }))
    const res = await SELF.fetch(`${ISSUER}/account/avatar`, {
      method: "POST",
      headers: { cookie: userCookie, origin: ISSUER },
      body: form,
      redirect: "manual",
    })
    expect(res.headers.get("location")).toContain("notice=invalid")
    expect((await getUserById(env, userId))?.avatarKey).toBeNull()
  })

  it("requires a session", async () => {
    const form = new FormData()
    form.set("avatar", new File([pngBytes()], "a.png", { type: "image/png" }))
    const res = await SELF.fetch(`${ISSUER}/account/avatar`, {
      method: "POST",
      body: form,
      redirect: "manual",
    })
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("/login")
  })

  it("replaces the previous object and deletes the superseded bytes", async () => {
    await uploadAvatar(pngBytes())
    const first = (await getUserById(env, userId))?.avatarKey ?? ""
    await uploadAvatar(pngBytes(256))
    const second = (await getUserById(env, userId))?.avatarKey ?? ""

    expect(second).not.toBe(first)
    expect(await env.AVATARS.head(first)).toBeNull()
    expect(await env.AVATARS.head(second)).not.toBeNull()
  })

  it("removes the avatar and its object on delete", async () => {
    await uploadAvatar(pngBytes())
    const key = (await getUserById(env, userId))?.avatarKey ?? ""
    const csrf = await freshCsrf()
    const res = await SELF.fetch(`${ISSUER}/account/avatar/delete`, {
      method: "POST",
      headers: {
        cookie: `${userCookie}; __Host-keyforge_csrf=${csrf}`,
        origin: ISSUER,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ csrf_token: csrf }).toString(),
      redirect: "manual",
    })
    expect(res.headers.get("location")).toContain("notice=avatar_removed")
    expect((await getUserById(env, userId))?.avatarKey).toBeNull()
    expect(await env.AVATARS.head(key)).toBeNull()
    expect((await SELF.fetch(`${ISSUER}/avatars/${key}`)).status).toBe(404)
  })
})

describe("asynchronous avatar upload", () => {
  it("answers JSON with the new picture URL when the uploader asks for it", async () => {
    const res = await uploadAvatar(pngBytes(), "avatar.png", "application/json")
    expect(res.status).toBe(200)
    const body = await res.json<{ ok: boolean; outcome: string; picture_url: string }>()
    expect(body.ok).toBe(true)
    expect(body.outcome).toBe("avatar_updated")
    const key = (await getUserById(env, userId))?.avatarKey
    expect(body.picture_url).toBe(`/avatars/${key}`)
  })

  it("reports a rejected type as JSON with a machine-readable error", async () => {
    const res = await uploadAvatar(
      new TextEncoder().encode("<svg></svg>"),
      "x.svg",
      "application/json",
    )
    expect(res.status).toBe(415)
    const body = await res.json<{ ok: boolean; error: string; max_bytes: number }>()
    expect(body.ok).toBe(false)
    expect(body.error).toBe("avatar_unsupported")
    expect(body.max_bytes).toBe(MAX_AVATAR_BYTES)
  })

  it("accepts an image far larger than the global 256 KB body limit", async () => {
    const res = await uploadAvatar(pngBytes(900 * 1024), "big.png", "application/json")
    expect(res.status).toBe(200)
    expect((await getUserById(env, userId))?.avatarKey).not.toBeNull()
  })

  it("rejects a body beyond the avatar ceiling without a bare error page", async () => {
    const res = await uploadAvatar(
      pngBytes(MAX_AVATAR_BYTES + 128 * 1024),
      "huge.png",
      "application/json",
    )
    expect(res.status).toBe(413)
    expect((await res.json<{ error: string }>()).error).toBe("avatar_too_large")
    expect((await getUserById(env, userId))?.avatarKey).toBeNull()
  })

  it("still redirects a plain form post so a no-JavaScript browser sees a page", async () => {
    const res = await uploadAvatar(pngBytes(), "avatar.png", "text/html")
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("notice=avatar_updated")
  })

  it("keeps the 256 KB limit on every other endpoint", async () => {
    const res = await SELF.fetch(`${ISSUER}/account/profile`, {
      method: "POST",
      headers: {
        cookie: userCookie,
        origin: ISSUER,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `name=${"x".repeat(300 * 1024)}`,
      redirect: "manual",
    })
    expect(res.status).toBe(413)
  })
})

describe("public avatar endpoint", () => {
  it("serves the image without any credentials and caches it immutably", async () => {
    await uploadAvatar(pngBytes())
    const key = (await getUserById(env, userId))?.avatarKey ?? ""

    const res = await SELF.fetch(`${ISSUER}/avatars/${key}`)
    expect(res.status).toBe(200)
    expect(res.headers.get("content-type")).toBe("image/png")
    expect(res.headers.get("cache-control")).toContain("immutable")
    expect(res.headers.get("x-content-type-options")).toBe("nosniff")
    expect(new Uint8Array(await res.arrayBuffer()).byteLength).toBe(128)

    const etag = res.headers.get("etag") ?? ""
    const revalidated = await SELF.fetch(`${ISSUER}/avatars/${key}`, {
      headers: { "if-none-match": etag },
    })
    expect(revalidated.status).toBe(304)
  })

  it("lets a relying party embed the image cross-origin", async () => {
    await uploadAvatar(pngBytes())
    const key = (await getUserById(env, userId))?.avatarKey ?? ""

    const res = await SELF.fetch(`${ISSUER}/avatars/${key}`)
    // An `<img>` is a no-CORS subresource, so the browser enforces CORP rather
    // than CORS. `same-origin` here would silently break every relying party
    // that renders the `picture` claim it was handed.
    expect(res.headers.get("cross-origin-resource-policy")).toBe("cross-origin")
    expect(res.headers.get("access-control-allow-origin")).toBe("*")
  })

  it("keeps identity pages same-origin", async () => {
    const res = await SELF.fetch(`${ISSUER}/login`)
    expect(res.headers.get("cross-origin-resource-policy")).toBe("same-origin")
  })

  it("returns 404 for a key that was never issued and refuses traversal", async () => {
    expect((await SELF.fetch(`${ISSUER}/avatars/${"a".repeat(43)}.png`)).status).toBe(404)
    expect((await SELF.fetch(`${ISSUER}/avatars/..%2F..%2Fetc%2Fpasswd`)).status).toBe(404)
  })

  it("exposes the avatar as an absolute picture claim under the profile scope", async () => {
    await uploadAvatar(pngBytes())
    const user = await getUserById(env, userId)
    if (user === null) throw new Error("user missing")
    const claims = buildUserClaims(env, user, ["openid", "profile"])
    expect(claims.picture).toBe(`${ISSUER}/avatars/${user.avatarKey}`)
  })
})

describe("admin avatar management", () => {
  it("uploads raw image bytes for another user and reports the picture URL", async () => {
    const res = await adminRequest("PUT", `/admin/users/${userId}/avatar`, pngBytes())
    expect(res.status).toBe(200)
    const body = await res.json<{ picture: string; content_type: string }>()
    expect(body.content_type).toBe("image/png")
    expect(body.picture).toContain(`${ISSUER}/avatars/`)

    const detail = await adminRequest("GET", `/admin/users/${userId}`)
    const detailBody = await detail.json<Record<string, unknown>>()
    expect(detailBody["has_avatar"]).toBe(true)
    expect(detailBody["picture"]).toBe(body.picture)
  })

  it("rejects a non-image body", async () => {
    const res = await adminRequest(
      "PUT",
      `/admin/users/${userId}/avatar`,
      new TextEncoder().encode("nope"),
    )
    expect(res.status).toBe(400)
    expect((await res.json<{ error: string }>()).error).toBe("avatar_unsupported")
  })

  it("deletes another user's avatar", async () => {
    await adminRequest("PUT", `/admin/users/${userId}/avatar`, pngBytes())
    const key = (await getUserById(env, userId))?.avatarKey ?? ""
    const res = await adminRequest("DELETE", `/admin/users/${userId}/avatar`)
    expect(res.status).toBe(200)
    expect((await res.json<{ deleted: boolean }>()).deleted).toBe(true)
    expect(await env.AVATARS.head(key)).toBeNull()
  })

  it("refuses avatar management from a non-admin session", async () => {
    const res = await SELF.fetch(`${ISSUER}/admin/users/${userId}/avatar`, {
      method: "DELETE",
      headers: { cookie: userCookie, origin: ISSUER, "sec-fetch-site": "same-origin" },
    })
    expect(res.status).toBe(403)
  })

  it("returns 404 for an unknown user", async () => {
    const res = await adminRequest("PUT", "/admin/users/usr_missing/avatar", pngBytes())
    expect(res.status).toBe(404)
  })
})
