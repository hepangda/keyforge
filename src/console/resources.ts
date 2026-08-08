import type { Context, Hono } from "hono"
import {
  createResource,
  deleteResource,
  getResourceByUri,
  listResources,
  updateResource,
} from "../db/queries/resources"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import { isSafeResourceUri } from "../security/redirect-uri"
import { safeLocalPath } from "../security/return-to"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import {
  type ResourceFormFeedback,
  type ResourceFormValues,
  renderResourceDeleteConfirmation,
  renderResourceForm,
  renderResourcesList,
} from "../views/console/resources"
import { chrome, parseLines, readVerifiedForm, withClearedDraft } from "./shared"

function resourceValues(form: FormData, currentUri = ""): ResourceFormValues {
  return {
    resourceUri: currentUri || readFormField(form, "resource_uri"),
    name: readFormField(form, "name"),
    allowedScopes: readFormField(form, "allowed_scopes"),
    enabled: form.get("enabled") !== null,
  }
}

function resourceError(
  c: Context<AppBindings>,
  resource: Awaited<ReturnType<typeof getResourceByUri>>,
  returnTo: string,
  feedback: ResourceFormFeedback,
): Response {
  return c.html(
    renderResourceForm(chrome(c, "resources"), resource, issueCsrfToken(c), returnTo, feedback),
    400,
  )
}

export function registerConsoleResources(app: Hono<AppBindings>): void {
  app.get("/console/resources", async (c) =>
    c.html(renderResourcesList(chrome(c, "resources"), await listResources(c.env))),
  )

  app.get("/console/resources/new", (c) =>
    c.html(
      renderResourceForm(
        chrome(c, "resources"),
        null,
        issueCsrfToken(c),
        safeLocalPath(c.req.query("return_to") ?? null),
      ),
    ),
  )

  app.post("/console/resources", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect("/console/resources/new?flash=invalid")
    const returnTo = safeLocalPath(readFormField(form, "return_to") || null)
    const values = resourceValues(form)
    const uri = values.resourceUri.trim()
    const name = values.name.trim()
    if (!isSafeResourceUri(uri)) {
      return resourceError(c, null, returnTo, {
        values,
        field: "resource_uri",
        error: "Enter a safe API resource URI.",
      })
    }
    if (name === "") {
      return resourceError(c, null, returnTo, {
        values,
        field: "name",
        error: "API names cannot be empty.",
      })
    }
    if ((await getResourceByUri(c.env, uri)) !== null) {
      return resourceError(c, null, returnTo, {
        values,
        field: "resource_uri",
        error: "That API resource URI is already registered.",
      })
    }
    await createResource(c.env, {
      resourceUri: uri,
      name,
      allowedScopes: parseLines(values.allowedScopes),
    })
    await recordAudit(c.env, {
      type: "admin.resource.created",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri: uri,
      requestId: c.get("requestId"),
      success: true,
    })
    if (returnTo !== "/") {
      const destination = new URL(returnTo, "https://keyforge.invalid")
      destination.searchParams.set("flash", "resource_created")
      return c.redirect(
        withClearedDraft(
          `${destination.pathname}${destination.search}${destination.hash}`,
          "keyforge:form:resource:new",
        ),
      )
    }
    return c.redirect(
      withClearedDraft(
        `/console/resources/${encodeURIComponent(uri)}?flash=resource_created`,
        "keyforge:form:resource:new",
      ),
    )
  })

  app.get("/console/resources/:id", async (c) => {
    const resource = await getResourceByUri(c.env, c.req.param("id"))
    if (resource === null) return c.redirect("/console/resources?flash=not_found")
    return c.html(renderResourceForm(chrome(c, "resources"), resource, issueCsrfToken(c)))
  })

  app.get("/console/resources/:id/delete", async (c) => {
    const resource = await getResourceByUri(c.env, c.req.param("id"))
    if (resource === null) return c.redirect("/console/resources?flash=not_found")
    return c.html(
      renderResourceDeleteConfirmation(chrome(c, "resources"), resource, issueCsrfToken(c)),
    )
  })

  app.post("/console/resources/:id/delete", async (c) => {
    const resourceUri = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(
        `/console/resources/${encodeURIComponent(resourceUri)}/delete?flash=invalid`,
      )
    }
    const resource = await getResourceByUri(c.env, resourceUri)
    if (resource === null) return c.redirect("/console/resources?flash=not_found")
    if (readFormField(form, "confirmation") !== resource.resourceUri) {
      return c.html(
        renderResourceDeleteConfirmation(
          chrome(c, "resources"),
          resource,
          issueCsrfToken(c),
          "The resource URI did not match. Nothing was deleted.",
        ),
        400,
      )
    }
    if (!(await deleteResource(c.env, resourceUri))) {
      return c.redirect("/console/resources?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.resource.deleted",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect("/console/resources?flash=resource_deleted")
  })

  app.post("/console/resources/:id", async (c) => {
    const uri = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/resources/${encodeURIComponent(uri)}?flash=invalid`)
    }
    const current = await getResourceByUri(c.env, uri)
    if (current === null) return c.redirect("/console/resources?flash=not_found")
    const values = resourceValues(form, current.resourceUri)
    const name = values.name.trim()
    if (name === "") {
      return resourceError(c, current, "/", {
        values,
        field: "name",
        error: "API names cannot be empty.",
      })
    }
    const updated = await updateResource(c.env, uri, {
      name,
      allowedScopes: parseLines(values.allowedScopes),
      enabled: values.enabled,
    })
    if (updated === null) return c.redirect("/console/resources?flash=not_found")
    await recordAudit(c.env, {
      type: "admin.resource.updated",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri: updated.resourceUri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect(
      withClearedDraft(
        `/console/resources/${encodeURIComponent(uri)}?flash=resource_updated`,
        `keyforge:form:resource:${encodeURIComponent(uri)}`,
      ),
    )
  })
}
