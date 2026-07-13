import type { Hono } from "hono"
import { z } from "zod"
import { revokeAllUserSessions } from "../auth/session"
import {
  createGroup,
  deleteGroup,
  getGroupByName,
  getUserById,
  getUserGroupNames,
  listGroups,
  listUsers,
  MAX_USER_GROUPS,
  setUserGroupsPreservingActiveAdmin,
  updateGroup,
  updateUser,
} from "../db/queries/users"
import { recordAudit } from "../security/audit"
import type { AppBindings } from "../types/app"
import type { User, UserType } from "../types/domain"
import { parsePagination, readJsonBody } from "../utils/http"
import { createManagedUser } from "./user-management"

const patchSchema = z.object({
  name: z.string().trim().min(1).max(120).nullable().optional(),
  userType: z.enum(["internal", "external"]).optional(),
  disabled: z.boolean().optional(),
  emailVerified: z.boolean().optional(),
})

const createUserSchema = z.object({
  email: z.email().max(254),
  name: z.string().trim().min(1).max(120).nullable().optional(),
  user_type: z.enum(["internal", "external"]),
  email_verified: z.boolean().default(false),
  password: z.string().min(12).max(128).optional(),
  group_ids: z.array(z.string().min(1)).max(MAX_USER_GROUPS).default([]),
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

function serializeUser(user: User, groups?: readonly string[]): Record<string, unknown> {
  const base: Record<string, unknown> = {
    id: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    name: user.name,
    picture: user.picture,
    user_type: user.userType,
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
    return c.json({ users: users.map((user) => serializeUser(user)) })
  })

  app.post("/admin/users", async (c) => {
    const parsed = createUserSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const body = parsed.data
    const result = await createManagedUser(c.env, {
      email: body.email,
      userType: body.user_type,
      emailVerified: body.email_verified,
      groupIds: body.group_ids,
      ...(body.name === undefined ? {} : { name: body.name }),
      ...(body.password === undefined ? {} : { password: body.password }),
    })
    if (!result.ok) {
      return c.json({ error: result.reason }, result.reason === "duplicate_email" ? 409 : 400)
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
        ...serializeUser(result.user, result.groups),
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
    return c.json(serializeUser(user, await getUserGroupNames(c.env, user.id)))
  })

  app.patch("/admin/users/:id", async (c) => {
    const parsed = patchSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const id = c.req.param("id")
    if ((await getUserById(c.env, id)) === null) {
      return c.json({ error: "not_found" }, 404)
    }
    const body = parsed.data
    const patch: {
      name?: string | null
      userType?: UserType
      disabled?: boolean
      emailVerified?: boolean
    } = {}
    if (body.name !== undefined) patch.name = body.name
    if (body.userType !== undefined) patch.userType = body.userType
    if (body.disabled !== undefined) patch.disabled = body.disabled
    if (body.emailVerified !== undefined) patch.emailVerified = body.emailVerified
    const updated = await updateUser(c.env, id, patch)
    if (updated === null) {
      return (await getUserById(c.env, id)) === null
        ? c.json({ error: "not_found" }, 404)
        : c.json({ error: "last_active_admin" }, 409)
    }
    await recordAudit(c.env, {
      type: "admin.user.updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: updated.id,
      requestId: c.get("requestId"),
      success: true,
      detail: `admin updated user ${updated.id}`,
    })
    return c.json(serializeUser(updated))
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

  app.post("/admin/users/:id/revoke-sessions", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) {
      return c.json({ error: "not_found" }, 404)
    }
    await revokeAllUserSessions(c.env, user.id)
    await recordAudit(c.env, {
      type: "admin.user.updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: `admin revoked all sessions for ${user.id}`,
    })
    return c.json({ revoked: true })
  })
}
