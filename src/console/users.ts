import type { Context, Hono } from "hono"
import { z } from "zod"
import { createManagedUser } from "../admin/user-management"
import { revokeAllUserSessions } from "../auth/session"
import {
  createGroup,
  deleteGroup,
  getGroupByName,
  getUserById,
  getUserGroupIds,
  listGroups,
  listUsers,
  MAX_USER_GROUPS,
  setUserGroupsPreservingActiveAdmin,
  updateGroup,
  updateUser,
} from "../db/queries/users"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import type { UserType } from "../types/domain"
import { readFormField } from "../utils/form"
import { parsePagination } from "../utils/http"
import {
  renderGroupDeleteConfirmation,
  renderUserCreate,
  renderUserDetail,
  renderUsersList,
  type UserCreateValues,
} from "../views/console/users"
import { chrome, readVerifiedForm } from "./shared"

const createUserSchema = z.object({
  email: z.email().max(254),
  name: z.string().trim().max(120),
  userType: z.enum(["internal", "external"]),
  emailVerified: z.boolean(),
  password: z.string().min(12).max(128).optional(),
  groupIds: z.array(z.string().min(1)).max(MAX_USER_GROUPS),
})

const setGroupsSchema = z.array(z.string().min(1)).max(MAX_USER_GROUPS)

const createGroupSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9._:-]*$/),
  description: z.string().trim().max(500),
})

function readGroupIds(form: FormData): string[] {
  return form.getAll("group_ids").filter((value): value is string => typeof value === "string")
}

function userCreateValues(form: FormData): UserCreateValues {
  return {
    email: readFormField(form, "email"),
    name: readFormField(form, "name"),
    userType: readFormField(form, "user_type") === "internal" ? "internal" : "external",
    emailVerified: form.get("email_verified") !== null,
    groupIds: readGroupIds(form),
  }
}

function passwordCleared(message: string, hadPassword: boolean): string {
  return hadPassword
    ? `${message} For security, the initial password was cleared; enter it again.`
    : message
}

async function renderUserCreateError(
  c: Context<AppBindings>,
  values: UserCreateValues,
  error: string,
): Promise<Response> {
  return c.html(
    renderUserCreate(chrome(c, "users"), await listGroups(c.env), issueCsrfToken(c), {
      values,
      error,
    }),
    400,
  )
}

export function registerConsoleUsers(app: Hono<AppBindings>): void {
  app.get("/console/users", async (c) => {
    const { limit, offset } = parsePagination(c)
    const [userPage, groups] = await Promise.all([
      listUsers(c.env, limit + 1, offset),
      listGroups(c.env),
    ])
    const hasNext = userPage.length > limit
    const users = userPage.slice(0, limit)
    return c.html(
      renderUsersList(chrome(c, "users"), users, groups, issueCsrfToken(c), limit, offset, hasNext),
    )
  })

  app.get("/console/users/new", async (c) =>
    c.html(renderUserCreate(chrome(c, "users"), await listGroups(c.env), issueCsrfToken(c))),
  )

  app.post("/console/users", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect("/console/users/new?flash=invalid")
    }
    const values = userCreateValues(form)
    const rawPassword = readFormField(form, "password")
    const rawUserType = readFormField(form, "user_type")
    const parsed = createUserSchema.safeParse({
      email: values.email.trim().toLowerCase(),
      name: values.name,
      userType: rawUserType,
      emailVerified: values.emailVerified,
      groupIds: values.groupIds,
      ...(rawPassword === "" ? {} : { password: rawPassword }),
    })
    if (!parsed.success) {
      const field = parsed.error.issues[0]?.path[0]
      const error =
        field === "email"
          ? "Enter a valid email address of at most 254 characters."
          : field === "name"
            ? "Display names must contain at most 120 characters."
            : field === "password"
              ? "Initial passwords must contain 12–128 characters."
              : field === "groupIds"
                ? `Select no more than ${MAX_USER_GROUPS} valid groups.`
                : "Choose a valid account type and check the form values."
      return renderUserCreateError(c, values, passwordCleared(error, rawPassword !== ""))
    }
    const data = parsed.data
    try {
      const result = await createManagedUser(c.env, {
        email: data.email,
        name: data.name === "" ? null : data.name,
        userType: data.userType,
        emailVerified: data.emailVerified,
        groupIds: data.groupIds,
        ...(data.password === undefined ? {} : { password: data.password }),
      })
      if (!result.ok) {
        return renderUserCreateError(
          c,
          values,
          passwordCleared(
            result.reason === "duplicate_email"
              ? "An account already uses that email address."
              : "One or more selected groups no longer exist. Review the group selection.",
            rawPassword !== "",
          ),
        )
      }
      await recordAudit(c.env, {
        type: "admin.user.created",
        actorUserId: c.get("user")?.id ?? null,
        userId: result.user.id,
        requestId: c.get("requestId"),
        success: true,
        detail: result.invitationSent
          ? "console created user and sent invitation"
          : "console created user with initial password",
      })
      return c.redirect(
        `/console/users/${result.user.id}?flash=${result.invitationSent ? "user_invited" : "user_created"}`,
      )
    } catch (error) {
      console.error("console.user_create_failed", c.get("requestId"), error)
      return c.redirect("/console/users/new?flash=user_create_failed")
    }
  })

  app.post("/console/groups", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect("/console/users?flash=invalid")
    }
    const parsed = createGroupSchema.safeParse({
      name: readFormField(form, "name").toLowerCase(),
      description: readFormField(form, "description"),
    })
    if (!parsed.success) {
      return c.redirect("/console/users?flash=invalid")
    }
    if ((await getGroupByName(c.env, parsed.data.name)) !== null) {
      return c.redirect("/console/users?flash=duplicate_group")
    }
    const group = await createGroup(
      c.env,
      parsed.data.name,
      parsed.data.description === "" ? null : parsed.data.description,
    )
    await recordAudit(c.env, {
      type: "admin.group.created",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      detail: `console created group ${group.name}`,
      metadata: { group_id: group.id },
    })
    return c.redirect("/console/users?flash=group_created")
  })

  app.post("/console/groups/:id", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect("/console/users?flash=invalid")
    const parsed = createGroupSchema.safeParse({
      name: readFormField(form, "name").trim().toLowerCase(),
      description: readFormField(form, "description").trim(),
    })
    if (!parsed.success) return c.redirect("/console/users?flash=invalid")
    const id = c.req.param("id")
    const result = await updateGroup(
      c.env,
      id,
      parsed.data.name,
      parsed.data.description === "" ? null : parsed.data.description,
    )
    if (result !== "updated") {
      return c.redirect(
        `/console/users?flash=${result === "not_found" ? "not_found" : result === "protected" ? "protected_group" : "duplicate_group"}`,
      )
    }
    await recordAudit(c.env, {
      type: "admin.group.updated",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: { group_id: id },
    })
    return c.redirect("/console/users?flash=group_updated")
  })

  app.get("/console/groups/:id/delete", async (c) => {
    const group = (await listGroups(c.env)).find((candidate) => candidate.id === c.req.param("id"))
    if (group === undefined) return c.redirect("/console/users?flash=not_found")
    if (group.name === "admins") return c.redirect("/console/users?flash=protected_group")
    return c.html(renderGroupDeleteConfirmation(chrome(c, "users"), group, issueCsrfToken(c)))
  })

  app.post("/console/groups/:id/delete", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/groups/${encodeURIComponent(id)}/delete?flash=invalid`)
    }
    const group = (await listGroups(c.env)).find((candidate) => candidate.id === id)
    if (group === undefined) return c.redirect("/console/users?flash=not_found")
    if (group.name === "admins") return c.redirect("/console/users?flash=protected_group")
    if (readFormField(form, "confirmation") !== group.name) {
      return c.html(
        renderGroupDeleteConfirmation(
          chrome(c, "users"),
          group,
          issueCsrfToken(c),
          "The group name did not match. Nothing was deleted.",
        ),
        400,
      )
    }
    const result = await deleteGroup(c.env, id)
    if (result !== "deleted") {
      return c.redirect(
        `/console/users?flash=${result === "protected" ? "protected_group" : "not_found"}`,
      )
    }
    await recordAudit(c.env, {
      type: "admin.group.deleted",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: { group_id: id },
    })
    return c.redirect("/console/users?flash=group_deleted")
  })

  app.get("/console/users/:id", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) {
      return c.redirect("/console/users?flash=not_found")
    }
    const [groups, selectedIds] = await Promise.all([
      listGroups(c.env),
      getUserGroupIds(c.env, user.id),
    ])
    return c.html(
      renderUserDetail(chrome(c, "users"), user, groups, new Set(selectedIds), issueCsrfToken(c)),
    )
  })

  app.post("/console/users/:id", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/users/${id}?flash=invalid`)
    }
    if ((await getUserById(c.env, id)) === null) {
      return c.redirect("/console/users?flash=not_found")
    }
    const name = readFormField(form, "name").trim()
    const userType: UserType =
      readFormField(form, "user_type") === "internal" ? "internal" : "external"
    const disabled = form.get("disabled") !== null
    const updated = await updateUser(c.env, id, {
      name: name === "" ? null : name,
      userType,
      emailVerified: form.get("email_verified") !== null,
      disabled,
    })
    if (updated === null) {
      return c.redirect(
        (await getUserById(c.env, id)) === null
          ? "/console/users?flash=not_found"
          : `/console/users/${id}?flash=last_admin`,
      )
    }
    await recordAudit(c.env, {
      type: "admin.user.updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: updated.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console updated user",
    })
    return c.redirect(`/console/users/${updated.id}?flash=user_updated`)
  })

  app.post("/console/users/:id/groups", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/users/${id}?flash=invalid`)
    }
    const user = await getUserById(c.env, id)
    if (user === null) {
      return c.redirect("/console/users?flash=not_found")
    }
    const parsedGroupIds = setGroupsSchema.safeParse(readGroupIds(form))
    if (!parsedGroupIds.success) {
      return c.redirect(`/console/users/${id}?flash=invalid_groups`)
    }
    const groupIds = [...new Set(parsedGroupIds.data)]
    const groups = await listGroups(c.env)
    const knownIds = new Set(groups.map((group) => group.id))
    if (groupIds.some((groupId) => !knownIds.has(groupId))) {
      return c.redirect(`/console/users/${id}?flash=invalid_groups`)
    }
    if (!(await setUserGroupsPreservingActiveAdmin(c.env, id, groupIds))) {
      return c.redirect(`/console/users/${id}?flash=last_admin`)
    }
    const names = groups.filter((group) => groupIds.includes(group.id)).map((group) => group.name)
    await recordAudit(c.env, {
      type: "admin.user.groups_updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console updated user groups",
      metadata: { groups: names },
    })
    return c.redirect(`/console/users/${user.id}?flash=groups_updated`)
  })

  app.post("/console/users/:id/revoke-sessions", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/users/${id}?flash=invalid`)
    }
    const user = await getUserById(c.env, id)
    if (user === null) {
      return c.redirect("/console/users?flash=not_found")
    }
    await revokeAllUserSessions(c.env, user.id)
    await recordAudit(c.env, {
      type: "admin.user.updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: user.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console revoked all sessions",
    })
    return c.redirect(`/console/users/${user.id}?flash=sessions_revoked`)
  })
}
