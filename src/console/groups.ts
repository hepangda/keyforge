import type { Context, Hono } from "hono"
import * as z from "zod"
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
  getPermissionGroupPolicy,
  replacePermissionGroupRules,
} from "../db/queries/permission-group-rules"
import { listResources } from "../db/queries/resources"
import {
  createGroup,
  deleteGroup,
  type GroupSummary,
  getGroupByName,
  isProtectedGroupName,
  listGroups,
  updateGroup,
} from "../db/queries/users"
import { PERMISSION_GROUP_PRIORITIES } from "../oauth/permission-rules"
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
  priority: z.coerce
    .number()
    .int()
    .min(PERMISSION_GROUP_PRIORITIES.minimum)
    .max(PERMISSION_GROUP_PRIORITIES.maximum),
})

async function groupById(env: Env, id: string): Promise<GroupSummary | undefined> {
  return (await listGroups(env)).find((candidate) => candidate.id === id)
}

async function renderAccessError(
  c: Context<AppBindings>,
  group: GroupSummary,
  rulesJson: string,
  error = "Enter a valid rule document using existing applications, APIs, and scopes.",
): Promise<Response> {
  const [clients, resources] = await Promise.all([listClients(c.env), listResources(c.env)])
  return c.html(
    renderGroupDetail(chrome(c, "groups"), {
      group,
      view: "access",
      csrfToken: issueCsrfToken(c),
      clients: clients.filter((client) => client.clientKind !== "service"),
      resources,
      rulesJson,
      accessError: error,
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
      visibility: readFormField(form, "visibility") === "hidden" ? "hidden" : "public",
      priority: readFormField(form, "priority"),
    }
    const parsed = groupSchema.safeParse({
      name: formValues.name.trim().toLowerCase(),
      description: formValues.description.trim(),
      priority: formValues.priority,
    })
    if (!parsed.success) {
      const issueField = parsed.error.issues[0]?.path[0]
      const field =
        issueField === "description"
          ? "description"
          : issueField === "priority"
            ? "priority"
            : "name"
      const feedback: GroupFormFeedback = {
        values: formValues,
        field,
        error:
          field === "description"
            ? "Descriptions must contain at most 500 characters."
            : field === "priority"
              ? "Priority must be a whole number from 0 to 1000000."
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
      formValues.visibility === "public",
      parsed.data.priority,
    )
    await recordAudit(c.env, {
      type: "admin.group.created",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      detail: `console created group ${group.name}`,
      metadata: { group_id: group.id, is_public: group.isPublic },
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
    const view =
      requestedView === "members"
        ? "members"
        : requestedView === "settings"
          ? "settings"
          : isProtectedGroupName(group.name) || requestedView === "access"
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
    const [policy, clients, resources] = await Promise.all([
      getPermissionGroupPolicy(c.env, group.id),
      listClients(c.env),
      listResources(c.env),
    ])
    if (policy === null) return c.redirect("/console/groups?flash=not_found")
    return c.html(
      renderGroupDetail(chrome(c, "groups"), {
        group,
        view,
        csrfToken: issueCsrfToken(c),
        clients: clients.filter((client) => client.clientKind !== "service"),
        resources,
        rules: policy.rules,
      }),
    )
  })

  app.post("/console/groups/:id/settings", async (c) => {
    const id = c.req.param("id")
    const group = await groupById(c.env, id)
    if (group === undefined) return c.redirect("/console/groups?flash=not_found")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/groups/${id}?view=settings&flash=invalid`)
    }
    const formValues: GroupFormValues = {
      name: readFormField(form, "name"),
      description: readFormField(form, "description"),
      visibility: readFormField(form, "visibility") === "hidden" ? "hidden" : "public",
      priority: readFormField(form, "priority"),
    }
    const parsed = groupSchema.safeParse({
      name: formValues.name.trim().toLowerCase(),
      description: formValues.description.trim(),
      priority: formValues.priority,
    })
    if (!parsed.success) {
      const issueField = parsed.error.issues[0]?.path[0]
      const field =
        issueField === "description"
          ? "description"
          : issueField === "priority"
            ? "priority"
            : "name"
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
                : field === "priority"
                  ? "Priority must be a whole number from 0 to 1000000."
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
      formValues.visibility === "public",
      parsed.data.priority,
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
      metadata: { group_id: id, is_public: formValues.visibility === "public" },
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
    const rulesJson = readFormField(form, "rules_json")
    let submitted: unknown
    try {
      submitted = JSON.parse(rulesJson)
    } catch {
      return renderAccessError(c, group, rulesJson, "Rule document must be valid JSON.")
    }
    const result = await replacePermissionGroupRules(c.env, id, submitted)
    if (result === "not_found") return c.redirect("/console/groups?flash=not_found")
    if (result !== "updated") {
      return renderAccessError(
        c,
        group,
        rulesJson,
        result === "standard_scope"
          ? "openid, profile, email, and offline_access cannot be configured in scope rules."
          : "Enter valid rules using existing applications, APIs, and configurable scopes.",
      )
    }
    const policy = await getPermissionGroupPolicy(c.env, id)
    if (policy === null) return c.redirect("/console/groups?flash=not_found")
    await recordAudit(c.env, {
      type: "admin.group.access_updated",
      actorUserId: c.get("user")?.id ?? null,
      requestId: c.get("requestId"),
      success: true,
      metadata: {
        group_id: id,
        priority: policy.priority,
        rules: policy.rules,
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
          : result === "protected"
            ? "protected_group"
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
    if (isProtectedGroupName(group.name)) {
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
    if (isProtectedGroupName(group.name)) {
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
