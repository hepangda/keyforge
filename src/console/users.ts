import type { Context, Hono } from "hono"
import { z } from "zod"
import { createManagedUser } from "../admin/user-management"
import { createMagicLink } from "../auth/magic-link"
import {
  addUserPassword,
  deletePasswordCredentialPreservingLoginMethod,
  listPasswordCredentials,
  minimumPasswordLength,
} from "../auth/password"
import { listSessionsByUser, revokeAllUserSessions } from "../auth/session"
import {
  ALIAS_PATTERN,
  getUserByAlias,
  getUserById,
  getUserGroupIds,
  isUserAdmin,
  listGroups,
  listUsers,
  MAX_ALIAS_LENGTH,
  MAX_USER_GROUPS,
  searchUsers,
  setUserGroupsPreservingActiveAdmin,
  updateUser,
  updateUserAlias,
} from "../db/queries/users"
import {
  deleteCredentialPreservingLoginMethod,
  listCredentialSummaries,
} from "../db/queries/webauthn"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import type { User } from "../types/domain"
import { readFormField } from "../utils/form"
import { parsePagination } from "../utils/http"
import {
  renderMagicLinkResult,
  renderUserActionConfirmation,
  renderUserCreate,
  renderUserDetail,
  renderUsersList,
  type UserCreateField,
  type UserCreateValues,
  type UserDetailFeedback,
  type UserDetailView,
} from "../views/console/users"
import { chrome, readVerifiedForm, withClearedDraft } from "./shared"

const createUserSchema = z.object({
  email: z.email().max(254),
  alias: z.string().min(1).max(MAX_ALIAS_LENGTH).regex(ALIAS_PATTERN),
  name: z.string().trim().max(120),
  emailVerified: z.boolean(),
  password: z.string().min(6).max(128).optional(),
  groupIds: z.array(z.string().min(1)).max(MAX_USER_GROUPS),
})

const setGroupsSchema = z.array(z.string().min(1)).max(MAX_USER_GROUPS)

function readGroupIds(form: FormData): string[] {
  return form.getAll("group_ids").filter((value): value is string => typeof value === "string")
}

function userCreateValues(form: FormData): UserCreateValues {
  return {
    email: readFormField(form, "email"),
    alias: readFormField(form, "alias"),
    name: readFormField(form, "name"),
    emailVerified: form.get("email_verified") !== null,
    groupIds: readGroupIds(form),
    setupMode: readFormField(form, "setup_mode") === "password" ? "password" : "invite",
  }
}

function passwordCleared(c: Context<AppBindings>, message: string, hadPassword: boolean): string {
  const localized = c.get("i18n").t(message)
  return hadPassword
    ? `${localized} ${c.get("i18n").t("For security, the initial password was cleared; enter it again.")}`
    : localized
}

async function renderUserCreateError(
  c: Context<AppBindings>,
  values: UserCreateValues,
  field: UserCreateField | null,
  error: string,
  hadPassword: boolean,
): Promise<Response> {
  return c.html(
    renderUserCreate(chrome(c, "users"), await listGroups(c.env), issueCsrfToken(c), {
      values,
      field,
      error: passwordCleared(c, error, hadPassword),
    }),
    400,
  )
}

function parseUserDetailView(raw: string | undefined): UserDetailView {
  return raw === "login-methods" || raw === "access" || raw === "sessions" ? raw : "profile"
}

async function renderUserDetailPage(
  c: Context<AppBindings>,
  user: User,
  view: UserDetailView,
  feedback?: UserDetailFeedback,
): Promise<Response> {
  const base = {
    user,
    view,
    csrfToken: issueCsrfToken(c),
    ...(feedback === undefined ? {} : { feedback }),
  }
  if (view === "login-methods") {
    const [passwords, passkeys, administrator] = await Promise.all([
      listPasswordCredentials(c.env, user.id),
      listCredentialSummaries(c.env, user.id),
      isUserAdmin(c.env, user.id),
    ])
    return c.html(
      renderUserDetail(chrome(c, "users"), {
        ...base,
        passwords,
        passkeys,
        passwordMinimum: minimumPasswordLength(administrator),
      }),
      feedback === undefined ? 200 : 400,
    )
  }
  if (view === "access") {
    const [groups, selectedIds] = await Promise.all([
      listGroups(c.env),
      getUserGroupIds(c.env, user.id),
    ])
    return c.html(
      renderUserDetail(chrome(c, "users"), {
        ...base,
        groups,
        selectedGroupIds: new Set(selectedIds),
      }),
    )
  }
  if (view === "sessions") {
    return c.html(
      renderUserDetail(chrome(c, "users"), {
        ...base,
        sessions: await listSessionsByUser(c.env, user.id),
      }),
    )
  }
  return c.html(renderUserDetail(chrome(c, "users"), base), feedback === undefined ? 200 : 400)
}

export function registerConsoleUsers(app: Hono<AppBindings>): void {
  app.get("/console/users", async (c) => {
    const { limit, offset } = parsePagination(c)
    const query = (c.req.query("q") ?? "").trim().slice(0, 120)
    const userPage =
      query === ""
        ? await listUsers(c.env, limit + 1, offset)
        : await searchUsers(c.env, query, limit + 1, offset)
    const hasNext = userPage.length > limit
    const users = userPage.slice(0, limit)
    return c.html(renderUsersList(chrome(c, "users"), users, query, limit, offset, hasNext))
  })

  app.get("/console/users/new", async (c) =>
    c.html(renderUserCreate(chrome(c, "users"), await listGroups(c.env), issueCsrfToken(c))),
  )

  app.post("/console/users", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect("/console/users/new?flash=invalid")
    const values = userCreateValues(form)
    const rawMode = readFormField(form, "setup_mode")
    const rawPassword = readFormField(form, "password")
    const confirmation = readFormField(form, "password_confirm")
    const hadPassword = rawPassword !== "" || confirmation !== ""
    if (rawMode !== "invite" && rawMode !== "password") {
      return renderUserCreateError(
        c,
        values,
        "setup_mode",
        "Choose how this user should set up their account.",
        hadPassword,
      )
    }
    if (values.setupMode === "password" && rawPassword !== confirmation) {
      return renderUserCreateError(
        c,
        values,
        "password_confirm",
        "The initial passwords must match.",
        hadPassword,
      )
    }
    const parsed = createUserSchema.safeParse({
      email: values.email.trim().toLowerCase(),
      alias: values.alias.trim(),
      name: values.name,
      emailVerified: values.emailVerified,
      groupIds: values.groupIds,
      ...(values.setupMode === "password" ? { password: rawPassword } : {}),
    })
    if (!parsed.success) {
      const issue = parsed.error.issues[0]
      const field = issue?.path[0]
      const mappedField: UserCreateField | null =
        field === "email"
          ? "email"
          : field === "alias"
            ? "alias"
            : field === "name"
              ? "name"
              : field === "password"
                ? "password"
                : field === "groupIds"
                  ? "group_ids"
                  : null
      const error =
        field === "email"
          ? "Enter a valid email address of at most 254 characters."
          : field === "alias"
            ? "Usernames may contain only English letters, numbers, hyphens, and underscores."
            : field === "name"
              ? "Display names must contain at most 120 characters."
              : field === "password"
                ? "Initial passwords must contain 6–128 characters (12 for administrators)."
                : field === "groupIds"
                  ? c
                      .get("i18n")
                      .t("Select no more than {max} valid groups.", { max: MAX_USER_GROUPS })
                  : "Check the form values."
      return renderUserCreateError(c, values, mappedField, error, hadPassword)
    }
    const data = parsed.data
    try {
      const result = await createManagedUser(c.env, {
        email: data.email,
        alias: data.alias,
        name: data.name === "" ? null : data.name,
        emailVerified: data.emailVerified,
        groupIds: data.groupIds,
        locale: c.get("i18n").locale,
        ...(values.setupMode === "password" && data.password !== undefined
          ? { password: data.password }
          : {}),
      })
      if (!result.ok) {
        const field: UserCreateField =
          result.reason === "duplicate_email"
            ? "email"
            : result.reason === "duplicate_alias"
              ? "alias"
              : result.reason === "invalid_password"
                ? "password"
                : "group_ids"
        return renderUserCreateError(
          c,
          values,
          field,
          result.reason === "duplicate_email"
            ? "An account already uses that email address."
            : result.reason === "duplicate_alias"
              ? "An account already uses that username."
              : result.reason === "invalid_password"
                ? "That password does not meet the policy for the selected groups."
                : "One or more selected groups no longer exist. Review the group selection.",
          hadPassword,
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
        withClearedDraft(
          `/console/users/${result.user.id}?view=login-methods&flash=${result.invitationSent ? "user_invited" : "user_created"}`,
          "keyforge:form:user:new",
        ),
      )
    } catch (error) {
      console.error("console.user_create_failed", c.get("requestId"), error)
      return c.redirect("/console/users/new?flash=user_create_failed")
    }
  })

  app.get("/console/users/:id", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.redirect("/console/users?flash=not_found")
    return renderUserDetailPage(c, user, parseUserDetailView(c.req.query("view")))
  })

  app.post("/console/users/:id", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=profile&flash=invalid`)
    const current = await getUserById(c.env, id)
    if (current === null) return c.redirect("/console/users?flash=not_found")
    const values = {
      alias: readFormField(form, "alias").trim(),
      name: readFormField(form, "name").trim(),
      emailVerified: form.get("email_verified") !== null,
    }
    if (!ALIAS_PATTERN.test(values.alias) || values.alias.length > MAX_ALIAS_LENGTH) {
      return renderUserDetailPage(c, current, "profile", {
        view: "profile",
        values,
        field: "alias",
        error: "Usernames may contain only English letters, numbers, hyphens, and underscores.",
      })
    }
    if (values.name.length > 120) {
      return renderUserDetailPage(c, current, "profile", {
        view: "profile",
        values,
        field: "name",
        error: "Display names must contain at most 120 characters.",
      })
    }
    const owner = await getUserByAlias(c.env, values.alias)
    if (owner !== null && owner.id !== id) {
      return renderUserDetailPage(c, current, "profile", {
        view: "profile",
        values,
        field: "alias",
        error: "An account already uses that username.",
      })
    }
    if (
      values.alias !== current.alias &&
      (await updateUserAlias(c.env, id, values.alias)) !== "updated"
    ) {
      return renderUserDetailPage(c, current, "profile", {
        view: "profile",
        values,
        field: "alias",
        error: "An account already uses that username.",
      })
    }
    const updated = await updateUser(c.env, id, {
      name: values.name === "" ? null : values.name,
      emailVerified: values.emailVerified,
    })
    if (updated === null) return c.redirect("/console/users?flash=not_found")
    await recordAudit(c.env, {
      type: "admin.user.updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: updated.id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console updated user profile",
    })
    return c.redirect(`/console/users/${updated.id}?view=profile&flash=user_updated`)
  })

  app.get("/console/users/:id/disable", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.redirect("/console/users?flash=not_found")
    if (user.disabled) return c.redirect(`/console/users/${user.id}?view=profile&flash=not_found`)
    return c.html(
      renderUserActionConfirmation(chrome(c, "users"), user, issueCsrfToken(c), "disable"),
    )
  })

  app.post("/console/users/:id/disable", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=profile&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const updated = await updateUser(c.env, id, { disabled: true })
    if (updated === null) return c.redirect(`/console/users/${id}?view=profile&flash=last_admin`)
    await recordAudit(c.env, {
      type: "admin.user.disabled",
      actorUserId: c.get("user")?.id ?? null,
      userId: id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console disabled user",
    })
    return c.redirect(`/console/users/${id}?view=profile&flash=user_updated`)
  })

  app.post("/console/users/:id/enable", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=profile&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    await updateUser(c.env, id, { disabled: false })
    await recordAudit(c.env, {
      type: "admin.user.enabled",
      actorUserId: c.get("user")?.id ?? null,
      userId: id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console enabled user",
    })
    return c.redirect(`/console/users/${id}?view=profile&flash=user_updated`)
  })

  app.post("/console/users/:id/groups", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=access&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const parsed = setGroupsSchema.safeParse(readGroupIds(form))
    if (!parsed.success) return c.redirect(`/console/users/${id}?view=access&flash=invalid_groups`)
    const groupIds = [...new Set(parsed.data)]
    const groups = await listGroups(c.env)
    const knownIds = new Set(groups.map((group) => group.id))
    if (groupIds.some((groupId) => !knownIds.has(groupId))) {
      return c.redirect(`/console/users/${id}?view=access&flash=invalid_groups`)
    }
    if (!(await setUserGroupsPreservingActiveAdmin(c.env, id, groupIds))) {
      return c.redirect(`/console/users/${id}?view=access&flash=last_admin`)
    }
    await recordAudit(c.env, {
      type: "admin.user.groups_updated",
      actorUserId: c.get("user")?.id ?? null,
      userId: id,
      requestId: c.get("requestId"),
      success: true,
      metadata: {
        groups: groups.filter((group) => groupIds.includes(group.id)).map((group) => group.name),
      },
    })
    return c.redirect(`/console/users/${id}?view=access&flash=groups_updated`)
  })

  app.post("/console/users/:id/passwords", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=login-methods&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const password = readFormField(form, "password")
    const passwordName = readFormField(form, "name").trim()
    if (password !== readFormField(form, "password_confirm")) {
      return renderUserDetailPage(c, user, "login-methods", {
        view: "login-methods",
        values: { passwordName },
        field: "password",
        error: "The new passwords must match.",
      })
    }
    const result = await addUserPassword(
      c.env,
      user.id,
      password,
      passwordName === "" ? null : passwordName,
    )
    if (result === null) {
      return renderUserDetailPage(c, user, "login-methods", {
        view: "login-methods",
        values: { passwordName },
        field: "password",
        error: "That password does not meet this user's policy.",
      })
    }
    await recordAudit(c.env, {
      type: "admin.user.password_added",
      actorUserId: c.get("user")?.id ?? null,
      userId: id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console added password login method",
    })
    return c.redirect(`/console/users/${id}?view=login-methods&flash=password_added`)
  })

  app.get("/console/users/:id/passwords/:credentialId/delete", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const credential = (await listPasswordCredentials(c.env, user.id)).find(
      (candidate) => candidate.id === c.req.param("credentialId"),
    )
    if (credential === undefined) {
      return c.redirect(`/console/users/${user.id}?view=login-methods&flash=not_found`)
    }
    return c.html(
      renderUserActionConfirmation(chrome(c, "users"), user, issueCsrfToken(c), "delete-password", {
        id: credential.id,
        name: credential.name ?? c.get("i18n").t("Password"),
      }),
    )
  })

  app.post("/console/users/:id/passwords/:credentialId/delete", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=login-methods&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const result = await deletePasswordCredentialPreservingLoginMethod(
      c.env,
      c.req.param("credentialId"),
      user.id,
    )
    if (result === "deleted") {
      await recordAudit(c.env, {
        type: "admin.user.password_deleted",
        actorUserId: c.get("user")?.id ?? null,
        userId: id,
        requestId: c.get("requestId"),
        success: true,
      })
    }
    return c.redirect(
      `/console/users/${id}?view=login-methods&flash=${result === "deleted" ? "password_deleted" : result === "last_login_method" ? "last_login_method" : "not_found"}`,
    )
  })

  app.get("/console/users/:id/passkeys/:credentialId/delete", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const credential = (await listCredentialSummaries(c.env, user.id)).find(
      (candidate) => candidate.id === c.req.param("credentialId"),
    )
    if (credential === undefined) {
      return c.redirect(`/console/users/${user.id}?view=login-methods&flash=not_found`)
    }
    return c.html(
      renderUserActionConfirmation(chrome(c, "users"), user, issueCsrfToken(c), "delete-passkey", {
        id: credential.id,
        name: credential.name ?? c.get("i18n").t("Passkey"),
      }),
    )
  })

  app.post("/console/users/:id/passkeys/:credentialId/delete", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=login-methods&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    const result = await deleteCredentialPreservingLoginMethod(
      c.env,
      c.req.param("credentialId"),
      user.id,
    )
    if (result === "deleted") {
      await recordAudit(c.env, {
        type: "admin.user.passkey_deleted",
        actorUserId: c.get("user")?.id ?? null,
        userId: id,
        requestId: c.get("requestId"),
        success: true,
      })
    }
    return c.redirect(
      `/console/users/${id}?view=login-methods&flash=${result === "deleted" ? "passkey_deleted" : result === "last_login_method" ? "last_login_method" : "not_found"}`,
    )
  })

  app.post("/console/users/:id/magic-link", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=login-methods&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    if (user.disabled) {
      return c.redirect(`/console/users/${id}?view=login-methods&flash=user_disabled`)
    }
    const link = await createMagicLink(c.env, { userId: user.id, redirectTo: "/" })
    await recordAudit(c.env, {
      type: "admin.user.magic_link.generated",
      actorUserId: c.get("user")?.id ?? null,
      userId: id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.html(renderMagicLinkResult(chrome(c, "users"), user, link.url))
  })

  app.get("/console/users/:id/revoke-sessions", async (c) => {
    const user = await getUserById(c.env, c.req.param("id"))
    if (user === null) return c.redirect("/console/users?flash=not_found")
    if ((await listSessionsByUser(c.env, user.id)).length === 0) {
      return c.redirect(`/console/users/${user.id}?view=sessions&flash=not_found`)
    }
    return c.html(
      renderUserActionConfirmation(chrome(c, "users"), user, issueCsrfToken(c), "revoke-sessions"),
    )
  })

  app.post("/console/users/:id/revoke-sessions", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/users/${id}?view=sessions&flash=invalid`)
    const user = await getUserById(c.env, id)
    if (user === null) return c.redirect("/console/users?flash=not_found")
    if ((await listSessionsByUser(c.env, user.id)).length === 0) {
      return c.redirect(`/console/users/${id}?view=sessions&flash=not_found`)
    }
    await revokeAllUserSessions(c.env, user.id)
    await recordAudit(c.env, {
      type: "admin.user.sessions_revoked",
      actorUserId: c.get("user")?.id ?? null,
      userId: id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console revoked all sessions",
    })
    return c.redirect(`/console/users/${id}?view=sessions&flash=sessions_revoked`)
  })
}
