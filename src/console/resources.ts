import type { Hono } from "hono"
import {
  createResource,
  getResourceByUri,
  listResources,
  updateResource,
} from "../db/queries/resources"
import { recordAudit } from "../security/audit"
import { issueCsrfToken } from "../security/csrf"
import { isSafeResourceUri } from "../security/redirect-uri"
import type { AppBindings } from "../types/app"
import { readFormField } from "../utils/form"
import { renderResourceForm, renderResourcesList } from "../views/console/resources"
import { chrome, parseLines, readVerifiedForm } from "./shared"

export function registerConsoleResources(app: Hono<AppBindings>): void {
  app.get("/console/resources", async (c) =>
    c.html(renderResourcesList(chrome(c, "resources"), await listResources(c.env))),
  )

  app.get("/console/resources/new", (c) =>
    c.html(renderResourceForm(chrome(c, "resources"), null, issueCsrfToken(c))),
  )

  app.post("/console/resources", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect("/console/resources/new?flash=invalid")
    }
    const uri = readFormField(form, "resource_uri").trim()
    const name = readFormField(form, "name").trim()
    if (!isSafeResourceUri(uri) || name === "" || (await getResourceByUri(c.env, uri)) !== null) {
      return c.redirect("/console/resources/new?flash=invalid")
    }
    await createResource(c.env, {
      resourceUri: uri,
      name,
      allowedScopes: parseLines(readFormField(form, "allowed_scopes")),
    })
    await recordAudit(c.env, {
      type: "admin.resource.created",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri: uri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect(`/console/resources/${encodeURIComponent(uri)}?flash=resource_created`)
  })

  app.get("/console/resources/:id", async (c) => {
    const resource = await getResourceByUri(c.env, c.req.param("id"))
    if (resource === null) {
      return c.redirect("/console/resources?flash=not_found")
    }
    return c.html(renderResourceForm(chrome(c, "resources"), resource, issueCsrfToken(c)))
  })

  app.post("/console/resources/:id", async (c) => {
    const uri = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/resources/${encodeURIComponent(uri)}?flash=invalid`)
    }
    const updated = await updateResource(c.env, uri, {
      name: readFormField(form, "name").trim(),
      allowedScopes: parseLines(readFormField(form, "allowed_scopes")),
      enabled: form.get("enabled") !== null,
    })
    if (updated === null) {
      return c.redirect("/console/resources?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.resource.updated",
      actorUserId: c.get("user")?.id ?? null,
      resourceUri: updated.resourceUri,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect(`/console/resources/${encodeURIComponent(uri)}?flash=resource_updated`)
  })
}
