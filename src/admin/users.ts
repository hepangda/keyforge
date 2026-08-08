import type { Context, Hono } from "hono"
import * as z from "zod"
import { createMagicLink } from "../auth/magic-link"
import {
  addUserPassword,
  deletePasswordCredentialPreservingLoginMethod,
  listPasswordCredentials,
} from "../auth/password"
import { revokeAllUserSessions } from "../auth/session"
import {
  getPermissionGroupAccess,
  MAX_PERMISSION_GROUP_TARGETS,
  replacePermissionGroupAccess,
} from "../db/queries/permission-group-access"
import {
  ALIAS_PATTERN,
  createGroup,
  deleteGroup,
  getGroupByName,
  getUserById,
  getUserGroupNames,
  listGroups,
  listUsers,
  MAX_ALIAS_LENGTH,
  MAX_USER_GROUPS,
  setUserGroupsPreservingActiveAdmin,
  updateGroup,
  updateUser,
  updateUserAlias,
} from "../db/queries/users"
import {
  deleteCredentialPreservingLoginMethod,
  listCredentialSummaries,
} from "../db/queries/webauthn"
import { MAX_AVATAR_BYTES } from "../media/avatar"
import { readAvatarUpload, removeUserAvatar, storeUserAvatar } from "../media/avatar-service"
import { effectivePictureUrl } from "../oidc/claims"
import { recordAudit } from "../security/audit"
import type { AppBindings } from "../types/app"
import type { User } from "../types/domain"
import { parsePagination, readJsonBody } from "../utils/http"
import { createManagedUser } from "./user-management"

const patchSchema = z
  .object({
    alias: z.string().trim().min(1).max(MAX_ALIAS_LENGTH).regex(ALIAS_PATTERN).optional(),
    name: z.string().trim().min(1).max(120).nullable().optional(),
    disabled: z.boolean().optional(),
    emailVerified: z.boolean().optional(),
  })
  .strict()

const createUserSchema = z.object({
  email: z.email().max(254),
  alias: z.string().trim().min(1).max(MAX_ALIAS_LENGTH).regex(ALIAS_PATTERN),
  name: z.string().trim().min(1).max(120).nullable().optional(),
  email_verified: z.boolean().default(false),
  password: z.string().min(6).max(128).optional(),
  group_ids: z.array(z.string().min(1)).max(MAX_USER_GROUPS).default([]),
})

const passwordSchema = z.object({
  password: z.string().min(6).max(128),
  name: z.string().trim().max(80).nullable().optional(),
})

const setGroupsSchema = z.object({
  group_ids: z.array(z.string().min(1)).max(MAX_USER_GROUPS),
})

const createGroupSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9._:-]*$/),
  description: z.string().trim().max(500).nullable().optional(),
})
const patchGroupSchema = createGroupSchema
  .partial()
  .refine((value) => Object.keys(value).length > 0)

const permissionGroupAccessSchema = z
  .object({
    client_ids: z.array(z.string().min(1)).max(MAX_PERMISSION_GROUP_TARGETS),
    resource_uris: z.array(z.string().min(1)).max(MAX_PERMISSION_GROUP_TARGETS),
  })
  .strict()

/** Read an admin avatar upload from either a multipart field or a raw body. */
async function readAdminAvatarBody(
  c: Context<AppBindings>,
): Promise<Uint8Array | "too_large" | "unsupported" | "empty"> {
  const contentType = c.req.header("content-type") ?? ""
  if (contentType.startsWith("multipart/form-data")) {
    const form = await c.req.raw.formData()
    const value = form.get("avatar")
    return await readAvatarUpload(typeof value === "string" ? value : (value as File | null))
  }
  const bytes = new Uint8Array(await c.req.raw.arrayBuffer())
  if (bytes.byteLength === 0) return "empty"
  if (bytes.byteLength > MAX_AVATAR_BYTES) return "too_large"
  return bytes
}

function serializeUser(env: Env, user: User, groups?: readonly string[]): Record<string, unknown> {
  const base: Record<string, unknown> = {
    id: user.id,
    email: user.email,
    alias: user.alias,
    email_verified: user.emailVerified,
    name: user.name,
    picture: effectivePictureUrl(env, user),
    has_avatar: user.avatarKey !== null,
    avatar_updated_at: user.avatarUpdatedAt,
    disabled: user.disabled,
    created_at: user.createdAt,
  }
  if (groups !== undefined) {
    base["groups"] = groups
  }
  return base
}

async function validateGroupIds(env: Env, groupIds: readonly string[]): Promise<boolean> {
  const known = new Set((await listGroups(env)).map((group) => group.id))
  return groupIds.every((id) => known.has(id))
}

export function registerAdminUsers(app: Hono<AppBindings>): void {
  app.get("/admin/users", async (c) => {
    const { limit, offset } = parsePagination(c)
    const users = await listUsers(c.env, limit, offset)
    return c.json({ users: users.map((user) => serializeUser(c.env, user)) })
  })

  app.post("/admin/users", async (c) => {
    const parsed = createUserSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const body = parsed.data
    const result = await createManagedUser(c.env, {
      email: body.email,
      alias: body.alias,
      emailVerified: body.email_verified,
      groupIds: body.group_ids,
      ...(body.name === undefined ? {} : { name: body.name }),
      ...(body.password === undefined ? {} : { password: body.password }),
    })
    if (!result.ok) {
      return c.json(
        { error: result.reason },
        result.reason === "duplicate_email" || result.reason === "duplicate_alias" ? 409 : 400,
      )
    }
    await recordAudit(c.env, {
      type: "admin.user.created",
      actorUserId: c.get("user")?.id ?? null,
      userId: result.user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: result.invitationSent
        ? "admin created user and sent invitation"
        : "admin created user with initial password",
    })
    return c.json(
      {
        ...serializeUser(c.env, result.user, result.groups),
        credential_setup: result.invitationSent ? "invitation_sent" : "password_set",
      },
      201,
    )
  })

  app.get("/admin/groups", async (c) => c.json({ groups: await listGroups(c.env) }))

  app.post("/admin/groups", async (c) => {
    const parsed = createGroupSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    if ((await getGroupByName(c.env, parsed.data.name)) !== null) {
      return c.json({ error: "duplicate_group" }, 409)
    }
    const group = await createGroup(c.env, parsed.data.name, parsed.data.description ?? null)
    await recordAudit(c.env, {
      type: "admin.group.created",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      detail: `admin created group ${group.name}`,
      metadata: { group_id: group.id },
    })
    return c.json(group, 201)
  })

  app.get("/admin/groups/:id", async (c) => {
    const group = (await listGroups(c.env)).find((entry) => entry.id === c.req.param("id"))
    return group === undefined ? c.json({ error: "not_found" }, 404) : c.json(group)
  })

  app.get("/admin/groups/:id/access", async (c) => {
    const access = await getPermissionGroupAccess(c.env, c.req.param("id"))
    return access === null
      ? c.json({ error: "not_found" }, 404)
      : c.json({ client_ids: access.clientIds, resource_uris: access.resourceUris })
  })

  app.put("/admin/groups/:id/access", async (c) => {
    const parsed = permissionGroupAccessSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) return c.json({ error: "invalid_request" }, 400)
    const id = c.req.param("id")
    const result = await replacePermissionGroupAccess(c.env, id, {
      clientIds: parsed.data.client_ids,
      resourceUris: parsed.data.resource_uris,
    })
    if (result === "not_found") return c.json({ error: "not_found" }, 404)
    if (result !== "updated") return c.json({ error: "invalid_access_target" }, 400)
    const access = await getPermissionGroupAccess(c.env, id)
    if (access === null) return c.json({ error: "not_found" }, 404)
    await recordAudit(c.env, {
      type: "admin.group.access_updated",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: {
        group_id: id,
        client_ids: access.clientIds,
        resource_uris: access.resourceUris,
      },
    })
    return c.json({ client_ids: access.clientIds, resource_uris: access.resourceUris })
  })

  app.patch("/admin/groups/:id", async (c) => {
    const parsed = patchGroupSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) return c.json({ error: "invalid_request" }, 400)
    const id = c.req.param("id")
    const current = (await listGroups(c.env)).find((entry) => entry.id === id)
    if (current === undefined) return c.json({ error: "not_found" }, 404)
    const result = await updateGroup(
      c.env,
      id,
      parsed.data.name ?? current.name,
      parsed.data.description === undefined ? current.description : parsed.data.description,
    )
    if (result !== "updated") {
      return c.json({ error: result === "protected" ? "protected_group" : "duplicate_group" }, 409)
    }
    await recordAudit(c.env, {
      type: "admin.group.updated",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: { group_id: id },
    })
    return c.json((await listGroups(c.env)).find((entry) => entry.id === id) ?? {})
  })

  app.delete("/admin/groups/:id", async (c) => {
    const id = c.req.param("id")
    const result = await deleteGroup(c.env, id)
    if (result !== "deleted") {
      return c.json(
        { error: result === "protected" ? "protected_group" : "not_found" },
        result === "protected" ? 409 : 404,
      )
    }
    await recordAudit(c.env, {
      type: "admin.group.deleted",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: { group_id: id },
    })
    return c.json({ deleted: true })
  })

  app.get("/admin/users/:id", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) {
      return c.json({ error: "not_found" }, 404)
    }
    return c.json(serializeUser(c.env, user, await getUserGroupNames(c.env, user.id)))
  })

  app.patch("/admin/users/:id", async (c) => {
    const parsed = patchSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const id = c.req.param("id")
    const current = await getUserById(c.env, id)
    if (current === null) {
      return c.json({ error: "not_found" }, 404)
    }
    const body = parsed.data
    const patch: {
      name?: string | null
      disabled?: boolean
      emailVerified?: boolean
    } = {}
    if (body.name !== undefined) patch.name = body.name
    if (body.alias !== undefined) {
      const aliasResult = await updateUserAlias(c.env, id, body.alias)
      if (aliasResult !== "updated") {
        return c.json(
          { error: aliasResult === "conflict" ? "duplicate_alias" : "not_found" },
          aliasResult === "conflict" ? 409 : 404,
        )
      }
    }
    if (body.disabled !== undefined) patch.disabled = body.disabled
    if (body.emailVerified !== undefined) patch.emailVerified = body.emailVerified
    const updated = await updateUser(c.env, id, patch)
    if (updated === null) {
      return (await getUserById(c.env, id)) === null
        ? c.json({ error: "not_found" }, 404)
        : c.json({ error: "last_active_admin" }, 409)
    }
    const changedProfile =
      body.name !== undefined || body.alias !== undefined || body.emailVerified !== undefined
    if (changedProfile) {
      await recordAudit(c.env, {
        type: "admin.user.updated",
        actorUserId: c.get("user")?.id ?? null,
        userId: updated.id,
        requestId: c.get("requestId"),
        success: true,
        detail: `admin updated user ${updated.id}`,
      })
    }
    if (body.disabled !== undefined && body.disabled !== current.disabled) {
      await recordAudit(c.env, {
        type: body.disabled ? "admin.user.disabled" : "admin.user.enabled",
        actorUserId: c.get("user")?.id ?? null,
        userId: updated.id,
        requestId: c.get("requestId"),
        success: true,
      })
    }
    return c.json(serializeUser(c.env, updated))
  })

  app.put("/admin/users/:id/groups", async (c) => {
    const parsed = setGroupsSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const id = c.req.param("id")
    const user = await getUserById(c.env, id)
    if (user === null) {
      return c.json({ error: "not_found" }, 404)
    }
    const groupIds = [...new Set(parsed.data.group_ids)]
    if (!(await validateGroupIds(c.env, groupIds))) {
      return c.json({ error: "invalid_groups" }, 400)
    }
    const groups = await listGroups(c.env)
    if (!(await setUserGroupsPreservingActiveAdmin(c.env, id, groupIds))) {
      return c.json({ error: "last_active_admin" }, 409)
    }
    const names = groups.filter((group) => groupIds.includes(group.id)).map((group) => group.name)
    await recordAudit(c.env, {
      type: "admin.user.groups_updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: `admin updated groups for ${user.id}`,
      metadata: { groups: names },
    })
    return c.json({ user_id: user.id, groups: names })
  })

  app.get("/admin/users/:id/login-methods", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    const [passwords, passkeys] = await Promise.all([
      listPasswordCredentials(c.env, user.id),
      listCredentialSummaries(c.env, user.id),
    ])
    return c.json({
      passwords,
      passkeys: passkeys.map((passkey) => ({
        id: passkey.id,
        name: passkey.name,
        createdAt: passkey.createdAt,
        lastUsedAt: passkey.lastUsedAt,
      })),
    })
  })

  app.post("/admin/users/:id/passwords", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    const parsed = passwordSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) return c.json({ error: "invalid_request" }, 400)
    const result = await addUserPassword(
      c.env,
      user.id,
      parsed.data.password,
      parsed.data.name ?? null,
    )
    if (result === null) return c.json({ error: "invalid_password_or_limit" }, 400)
    await recordAudit(c.env, {
      type: "admin.user.password_added",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "admin added password login method",
    })
    return c.json({ id: result.id }, 201)
  })

  app.delete("/admin/users/:id/passwords/:credentialId", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    const result = await deletePasswordCredentialPreservingLoginMethod(
      c.env,
      c.req.param("credentialId"),
      user.id,
    )
    if (result !== "deleted") {
      return c.json({ error: result }, result === "last_login_method" ? 409 : 404)
    }
    await recordAudit(c.env, {
      type: "admin.user.password_deleted",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "admin deleted password login method",
    })
    return c.json({ deleted: true })
  })

  app.delete("/admin/users/:id/passkeys/:credentialId", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    const result = await deleteCredentialPreservingLoginMethod(
      c.env,
      c.req.param("credentialId"),
      user.id,
    )
    if (result !== "deleted") {
      return c.json({ error: result }, result === "last_login_method" ? 409 : 404)
    }
    await recordAudit(c.env, {
      type: "admin.user.passkey_deleted",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "admin deleted passkey login method",
    })
    return c.json({ deleted: true })
  })

  // Accepts the raw image bytes with the real content type sniffed from the
  // body, so an operator can pipe a file in without multipart framing.
  app.put("/admin/users/:id/avatar", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    const declaredLength = Number(c.req.header("content-length") ?? "0")
    if (Number.isFinite(declaredLength) && declaredLength > MAX_AVATAR_BYTES) {
      return c.json({ error: "avatar_too_large" }, 413)
    }
    const body = await readAdminAvatarBody(c)
    if (typeof body === "string") {
      return c.json({ error: `avatar_${body}` }, body === "too_large" ? 413 : 400)
    }
    const result = await storeUserAvatar(c.env, user.id, body)
    if (result.status === "rejected") {
      return c.json({ error: `avatar_${result.reason}` }, result.reason === "too_large" ? 413 : 400)
    }
    if (result.status === "not_found") return c.json({ error: "not_found" }, 404)
    await recordAudit(c.env, {
      type: "admin.user.updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "admin updated avatar",
    })
    const updated = await getUserById(c.env, user.id)
    return c.json({
      picture: updated === null ? null : effectivePictureUrl(c.env, updated),
      content_type: result.contentType,
    })
  })

  app.delete("/admin/users/:id/avatar", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    const removed = await removeUserAvatar(c.env, user.id)
    if (removed) {
      await recordAudit(c.env, {
        type: "admin.user.updated",
        actorUserId: c.get("user")?.id ?? null,
        userId: user.id,
        requestId: c.get("requestId"),
        success: true,
        detail: "admin removed avatar",
      })
    }
    return c.json({ deleted: removed })
  })

  app.post("/admin/users/:id/magic-link", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.json({ error: "not_found" }, 404)
    if (user.disabled) return c.json({ error: "account_disabled" }, 409)
    const link = await createMagicLink(c.env, {
      userId: user.id,
      redirectTo: "/",
    })
    await recordAudit(c.env, {
      type: "admin.user.magic_link.generated",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.json({ url: link.url, expires_in: 15 * 60 })
  })

  app.post("/admin/users/:id/revoke-sessions", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) {
      return c.json({ error: "not_found" }, 404)
    }
    await revokeAllUserSessions(c.env, user.id)
    await recordAudit(c.env, {
      type: "admin.user.sessions_revoked",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: `admin revoked all sessions for ${user.id}`,
    })
    return c.json({ revoked: true })
  })
}
