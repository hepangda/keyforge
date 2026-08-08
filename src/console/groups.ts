import type { Context, Hono } from "hono"
import { z } from "zod"
import { listClients } from "../db/queries/clients"
import {
  addUserToPermissionGroup,
  approvePermissionGroupMembershipRequest,
  listGroupMembers,
  listPendingGroupMembershipRequests,
  rejectPermissionGroupMembershipRequest,
  removeUserFromPermissionGroup,
  searchGroupMemberCandidates,
} from "../db/queries/group-memberships"
import {
  getPermissionGroupAccess,
  MAX_PERMISSION_GROUP_TARGETS,
  type PermissionGroupAccess,
  replacePermissionGroupAccess,
} from "../db/queries/permission-group-access"
import { listResources } from "../db/queries/resources"
import {
  createGroup,
  deleteGroup,
  type GroupSummary,
  getGroupByName,
  listGroups,
  updateGroup,
} from "../db/queries/users"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import { parsePagination } from "../utils/http"
import {
  type GroupFormFeedback,
  type GroupFormValues,
  renderGroupCreateForm,
  renderGroupDeleteConfirmation,
  renderGroupDetail,
  renderGroupsList,
} from "../views/console/groups"
import { chrome, readVerifiedForm, withClearedDraft } from "./shared"

const groupSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9._:-]*$/),
  description: z.string().trim().max(500),
})

async function groupById(env: Env, id: string): Promise<GroupSummary | undefined> {
  return (await listGroups(env)).find((candidate) => candidate.id === id)
}

function submittedAccess(form: FormData): PermissionGroupAccess {
  const clientIds = form
    .getAll("client_ids")
    .flatMap((value) => (typeof value === "string" && value !== "" ? [value] : []))
  const resourceUris = form
    .getAll("resource_uris")
    .flatMap((value) => (typeof value === "string" && value !== "" ? [value] : []))
  return {
    clientIds: [...new Set(clientIds)],
    resourceUris: [...new Set(resourceUris)],
  }
}

async function renderAccessError(
  c: Context<AppBindings>,
  group: GroupSummary,
  submitted: PermissionGroupAccess,
): Promise<Response> {
  const [clients, resources] = await Promise.all([listClients(c.env), listResources(c.env)])
  const userClients = clients.filter((client) => client.clientKind !== "service")
  const validClientIds = new Set<string>(userClients.map((client) => client.clientId))
  const validResourceUris = new Set<string>(resources.map((resource) => resource.resourceUri))
  return c.html(
    renderGroupDetail(chrome(c, "groups"), {
      group,
      view: "access",
      csrfToken: issueCsrfToken(c),
      clients: userClients,
      resources,
      selectedClientIds: new Set(
        submitted.clientIds.filter((clientId) => validClientIds.has(clientId)),
      ),
      selectedResourceUris: new Set(
        submitted.resourceUris.filter((resourceUri) => validResourceUris.has(resourceUri)),
      ),
      accessError: "Choose only existing user applications and APIs.",
    }),
    400,
  )
}

export function registerConsoleGroups(app: Hono<AppBindings>): void {
  app.get("/console/groups", async (c) =>
    c.html(renderGroupsList(chrome(c, "groups"), await listGroups(c.env))),
  )

  app.get("/console/groups/new", (c) =>
    c.html(renderGroupCreateForm(chrome(c, "groups"), issueCsrfToken(c))),
  )

  app.post("/console/groups", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect("/console/groups/new?flash=invalid")
    const formValues: GroupFormValues = {
      name: readFormField(form, "name"),
      description: readFormField(form, "description"),
    }
    const parsed = groupSchema.safeParse({
      name: formValues.name.trim().toLowerCase(),
      description: formValues.description.trim(),
    })
    if (!parsed.success) {
      const field = parsed.error.issues[0]?.path[0] === "description" ? "description" : "name"
      const feedback: GroupFormFeedback = {
        values: formValues,
        field,
        error:
          field === "description"
            ? "Descriptions must contain at most 500 characters."
            : "Enter a valid group name of at most 64 characters.",
      }
      return c.html(renderGroupCreateForm(chrome(c, "groups"), issueCsrfToken(c), feedback), 400)
    }
    if ((await getGroupByName(c.env, parsed.data.name)) !== null) {
      return c.html(
        renderGroupCreateForm(chrome(c, "groups"), issueCsrfToken(c), {
          values: formValues,
          field: "name",
          error: "A group with that name already exists.",
        }),
        400,
      )
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
    return c.redirect(
      withClearedDraft(
        `/console/groups/${group.id}?view=settings&flash=group_created`,
        "keyforge:form:group:new",
      ),
    )
  })

  app.get("/console/groups/:id", async (c) => {
    const group = await groupById(c.env, c.req.param("id"))
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const requestedView = c.req.query("view")
    if (group.name === "admins" && requestedView === "settings") {
      return c.redirect(`/console/groups/${group.id}?view=access&flash=protected_group`)
    }
    const view =
      requestedView === "members"
        ? "members"
        : group.name === "admins" || requestedView === "access"
          ? "access"
          : "settings"
    if (view === "settings") {
      return c.html(
        renderGroupDetail(chrome(c, "groups"), {
          group,
          view,
          csrfToken: issueCsrfToken(c),
        }),
      )
    }
    if (view === "members") {
      const { limit, offset } = parsePagination(c)
      const query = (c.req.query("q") ?? "").trim().slice(0, 120)
      const [memberPage, requests, candidates] = await Promise.all([
        listGroupMembers(c.env, group.id, limit + 1, offset),
        listPendingGroupMembershipRequests(c.env, group.id, 50),
        searchGroupMemberCandidates(c.env, group.id, query, 8),
      ])
      return c.html(
        renderGroupDetail(chrome(c, "groups"), {
          group,
          view,
          csrfToken: issueCsrfToken(c),
          members: memberPage.slice(0, limit),
          memberLimit: limit,
          memberOffset: offset,
          memberHasNext: memberPage.length > limit,
          membershipRequests: requests,
          memberCandidates: candidates,
          memberQuery: query,
        }),
      )
    }
    const [access, clients, resources] = await Promise.all([
      getPermissionGroupAccess(c.env, group.id),
      listClients(c.env),
      listResources(c.env),
    ])
    if (access === null) return c.redirect("/console/groups?flash=not_found")
    return c.html(
      renderGroupDetail(chrome(c, "groups"), {
        group,
        view,
        csrfToken: issueCsrfToken(c),
        clients: clients.filter((client) => client.clientKind !== "service"),
        resources,
        selectedClientIds: new Set(access.clientIds),
        selectedResourceUris: new Set(access.resourceUris),
      }),
    )
  })

  app.post("/console/groups/:id/settings", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    if (group.name === "admins") {
      return c.redirect(`/console/groups/${id}?view=access&flash=protected_group`)
    }
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/groups/${id}?view=settings&flash=invalid`)
    }
    const formValues: GroupFormValues = {
      name: readFormField(form, "name"),
      description: readFormField(form, "description"),
    }
    const parsed = groupSchema.safeParse({
      name: formValues.name.trim().toLowerCase(),
      description: formValues.description.trim(),
    })
    if (!parsed.success) {
      const field = parsed.error.issues[0]?.path[0] === "description" ? "description" : "name"
      return c.html(
        renderGroupDetail(chrome(c, "groups"), {
          group,
          view: "settings",
          csrfToken: issueCsrfToken(c),
          settingsFeedback: {
            values: formValues,
            field,
            error:
              field === "description"
                ? "Descriptions must contain at most 500 characters."
                : "Enter a valid group name of at most 64 characters.",
          },
        }),
        400,
      )
    }
    const owner = await getGroupByName(c.env, parsed.data.name)
    if (owner !== null && owner.id !== id) {
      return c.html(
        renderGroupDetail(chrome(c, "groups"), {
          group,
          view: "settings",
          csrfToken: issueCsrfToken(c),
          settingsFeedback: {
            values: formValues,
            field: "name",
            error: "A group with that name already exists.",
          },
        }),
        400,
      )
    }
    const result = await updateGroup(
      c.env,
      id,
      parsed.data.name,
      parsed.data.description === "" ? null : parsed.data.description,
    )
    if (result !== "updated") {
      return c.redirect(
        `/console/groups?flash=${result === "protected" ? "protected_group" : result === "conflict" ? "duplicate_group" : "not_found"}`,
      )
    }
    await recordAudit(c.env, {
      type: "admin.group.updated",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: { group_id: id },
    })
    return c.redirect(
      withClearedDraft(
        `/console/groups/${id}?view=settings&flash=group_updated`,
        `keyforge:form:group:${id}:settings`,
      ),
    )
  })

  app.post("/console/groups/:id/access", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/groups/${id}?view=access&flash=invalid`)
    const submitted = submittedAccess(form)
    if (
      submitted.clientIds.length > MAX_PERMISSION_GROUP_TARGETS ||
      submitted.resourceUris.length > MAX_PERMISSION_GROUP_TARGETS
    ) {
      return renderAccessError(c, group, submitted)
    }
    const result = await replacePermissionGroupAccess(c.env, id, submitted)
    if (result === "not_found") return c.redirect("/console/groups?flash=not_found")
    if (result !== "updated") return renderAccessError(c, group, submitted)
    const access = await getPermissionGroupAccess(c.env, id)
    if (access === null) return c.redirect("/console/groups?flash=not_found")
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
    return c.redirect(
      withClearedDraft(
        `/console/groups/${id}?view=access&flash=group_access_updated`,
        `keyforge:form:group:${id}:access`,
      ),
    )
  })

  app.post("/console/groups/:id/members", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/groups/${id}?view=members&flash=invalid`)
    const userId = readFormField(form, "user_id")
    const result = await addUserToPermissionGroup(c.env, id, userId)
    if (result === "added") {
      await recordAudit(c.env, {
        type: "admin.group.member_added",
        actorUserId: c.get("user")?.id ?? null,
        userId,
        requestId: c.get("requestId"),
        success: true,
        metadata: { group_id: id },
      })
    }
    const flash =
      result === "added"
        ? "group_member_added"
        : result === "already_member"
          ? "group_member_exists"
          : result === "limit"
            ? "group_member_limit"
            : "not_found"
    return c.redirect(`/console/groups/${id}?view=members&flash=${flash}`)
  })

  app.post("/console/groups/:id/members/:userId/remove", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/groups/${id}?view=members&flash=invalid`)
    const userId = c.req.param("userId")
    const result = await removeUserFromPermissionGroup(c.env, id, userId)
    if (result === "removed") {
      await recordAudit(c.env, {
        type: "admin.group.member_removed",
        actorUserId: c.get("user")?.id ?? null,
        userId,
        requestId: c.get("requestId"),
        success: true,
        metadata: { group_id: id },
      })
    }
    const flash =
      result === "removed"
        ? "group_member_removed"
        : result === "last_admin"
          ? "last_admin"
          : "not_found"
    return c.redirect(`/console/groups/${id}?view=members&flash=${flash}`)
  })

  app.post("/console/groups/:id/requests/:userId/approve", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/groups/${id}?view=members&flash=invalid`)
    const userId = c.req.param("userId")
    const result = await approvePermissionGroupMembershipRequest(c.env, id, userId)
    if (result === "added" || result === "already_member") {
      await recordAudit(c.env, {
        type: "admin.group.membership_request_approved",
        actorUserId: c.get("user")?.id ?? null,
        userId,
        requestId: c.get("requestId"),
        success: true,
        metadata: { group_id: id },
      })
    }
    const flash =
      result === "added" || result === "already_member"
        ? "group_request_approved"
        : result === "limit"
          ? "group_member_limit"
          : "not_found"
    return c.redirect(`/console/groups/${id}?view=members&flash=${flash}`)
  })

  app.post("/console/groups/:id/requests/:userId/reject", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/groups/${id}?view=members&flash=invalid`)
    const userId = c.req.param("userId")
    const rejected = await rejectPermissionGroupMembershipRequest(c.env, id, userId)
    if (rejected) {
      await recordAudit(c.env, {
        type: "admin.group.membership_request_rejected",
        actorUserId: c.get("user")?.id ?? null,
        userId,
        requestId: c.get("requestId"),
        success: true,
        metadata: { group_id: id },
      })
    }
    return c.redirect(
      `/console/groups/${id}?view=members&flash=${rejected ? "group_request_rejected" : "not_found"}`,
    )
  })
  app.get("/console/groups/:id/delete", async (c) => {
    const group = await groupById(c.env, c.req.param("id"))
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    if (group.name === "admins") {
      return c.redirect(`/console/groups/${group.id}?view=access&flash=protected_group`)
    }
    return c.html(renderGroupDeleteConfirmation(chrome(c, "groups"), group, issueCsrfToken(c)))
  })

  app.post("/console/groups/:id/delete", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/groups/${id}/delete?flash=invalid`)
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    if (group.name === "admins") {
      return c.redirect(`/console/groups/${id}?view=access&flash=protected_group`)
    }
    if (readFormField(form, "confirmation") !== group.name) {
      return c.html(
        renderGroupDeleteConfirmation(
          chrome(c, "groups"),
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
        `/console/groups?flash=${result === "protected" ? "protected_group" : "not_found"}`,
      )
    }
    await recordAudit(c.env, {
      type: "admin.group.deleted",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: { group_id: id },
    })
    return c.redirect("/console/groups?flash=group_deleted")
  })
}
