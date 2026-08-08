import type { Context, Hono } from "hono"
import {
  createClient,
  deleteClient,
  getClientById,
  listClientsPaginated,
  setClientEnabled,
  setClientSecretHash,
  updateClient,
} from "../db/queries/clients"
import { listResources } from "../db/queries/resources"
import type { I18n } from "../i18n"
import { type ClientConfiguration, validateClientConfiguration } from "../oauth/client-config"
import { isSafePostLogoutRedirectUri } from "../oauth/post-logout"
import { recordAudit } from "../security/audit"
import { generateClientSecret, hashClientSecret } from "../security/client-secret"
import { issueCsrfToken } from "../security/csrf"
import { isSafeOAuthRedirectUri } from "../security/redirect-uri"
import type { AppBindings } from "../types/app"
import type { ClientKind, ClientType, OAuthClient } from "../types/domain"
import { readFormField } from "../utils/form"
import { parsePagination } from "../utils/http"
import {
  type ClientDetailView,
  type ClientFormField,
  type ClientFormValues,
  renderClientActionConfirmation,
  renderClientDetail,
  renderClientForm,
  renderClientSecret,
  renderClientsList,
} from "../views/console/clients"
import { chrome, parseLines, readVerifiedForm, withClearedDraft } from "./shared"

function parseType(raw: string): ClientType {
  return raw === "confidential" ? "confidential" : "public"
}

function parseKind(raw: string): ClientKind {
  return raw === "device" || raw === "service" ? raw : "application"
}

function readClientFormValues(form: FormData, current?: OAuthClient): ClientFormValues {
  const allowedResources = form
    .getAll("allowed_resources")
    .flatMap((value) => (typeof value === "string" ? [value] : []))
    .join("\n")
  return {
    clientId: current?.clientId ?? readFormField(form, "client_id"),
    name: readFormField(form, "name"),
    type: current?.type ?? parseType(readFormField(form, "type")),
    clientKind: current?.clientKind ?? parseKind(readFormField(form, "client_kind")),
    redirectUris: readFormField(form, "redirect_uris"),
    postLogoutRedirectUris: readFormField(form, "post_logout_redirect_uris"),
    allowedScopes: readFormField(form, "allowed_scopes"),
    allowedGrantTypes: readFormField(form, "allowed_grant_types"),
    allowedResources,
    defaultResource: readFormField(form, "default_resource"),
  }
}
function clientValues(client: OAuthClient): ClientFormValues {
  return {
    clientId: client.clientId,
    name: client.name,
    type: client.type,
    clientKind: client.clientKind,
    redirectUris: client.redirectUris.join("\n"),
    postLogoutRedirectUris: client.postLogoutRedirectUris.join("\n"),
    allowedScopes: client.allowedScopes.join("\n"),
    allowedGrantTypes: client.allowedGrantTypes.join("\n"),
    allowedResources: client.allowedResources.join("\n"),
    defaultResource: client.defaultResource ?? "",
  }
}

function parseClientDetailView(raw: string | undefined): ClientDetailView {
  return raw === "access" || raw === "security" ? raw : "settings"
}

function clientConfiguration(values: ClientFormValues): ClientConfiguration {
  return {
    clientId: values.clientId.trim(),
    name: values.name.trim(),
    type: values.type,
    clientKind: values.clientKind,
    redirectUris: parseLines(values.redirectUris),
    postLogoutRedirectUris: parseLines(values.postLogoutRedirectUris),
    allowedScopes: parseLines(values.allowedScopes),
    allowedGrantTypes: parseLines(values.allowedGrantTypes),
    allowedResources: parseLines(values.allowedResources),
    defaultResource: values.defaultResource.trim() || null,
  }
}

type ClientFormIssue = {
  readonly error: string
  readonly field: ClientFormField | null
  readonly initialStep: 0 | 1 | 2 | 3
}

async function clientConfigurationError(
  env: Env,
  configuration: ClientConfiguration,
  i18n: I18n,
): Promise<ClientFormIssue | undefined> {
  if (!configuration.redirectUris.every(isSafeOAuthRedirectUri)) {
    return {
      error: i18n.t(
        "Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain native scheme, without credentials or fragments.",
      ),
      field: "redirect_uris",
      initialStep: 1,
    }
  }
  if (!configuration.postLogoutRedirectUris.every(isSafePostLogoutRedirectUri)) {
    return {
      error: i18n.t(
        "Post-logout redirect URIs must use HTTPS or loopback HTTP, without credentials or fragments.",
      ),
      field: "post_logout_redirect_uris",
      initialStep: 1,
    }
  }
  const validation = await validateClientConfiguration(env, configuration)
  if (validation.ok) return undefined
  const reason = validation.reason
  const field: ClientFormField | null = reason.startsWith("client_id")
    ? "client_id"
    : reason.startsWith("name")
      ? "name"
      : reason.includes("allowed_scopes") || reason.includes("scopes")
        ? "allowed_scopes"
        : reason.includes("allowed_grant_types") || reason.includes("grant")
          ? "allowed_grant_types"
          : reason.includes("default_resource")
            ? "default_resource"
            : reason.includes("resource")
              ? "allowed_resources"
              : null
  return {
    error: i18n.t("Configuration error: {reason}.", { reason: i18n.t(reason) }),
    field,
    initialStep: field === "client_id" || field === "name" ? 0 : field === null ? 3 : 2,
  }
}

async function renderClientFormError(
  c: Context<AppBindings>,
  client: OAuthClient | null,
  values: ClientFormValues,
  issue: ClientFormIssue,
): Promise<Response> {
  const resources = client === null ? await listResources(c.env) : []
  return c.html(
    renderClientForm(
      chrome(c, "clients"),
      client,
      issueCsrfToken(c),
      { values, ...issue },
      resources,
    ),
    400,
  )
}
async function renderClientDetailError(
  c: Context<AppBindings>,
  client: OAuthClient,
  view: "settings" | "access",
  values: ClientFormValues,
  issue: ClientFormIssue,
): Promise<Response> {
  return c.html(
    renderClientDetail(
      chrome(c, "clients"),
      client,
      view,
      issueCsrfToken(c),
      view === "access" ? await listResources(c.env) : [],
      { values, ...issue },
    ),
    400,
  )
}

export function registerConsoleClients(app: Hono<AppBindings>): void {
  app.get("/console/clients", async (c) => {
    const { limit, offset } = parsePagination(c)
    const page = await listClientsPaginated(c.env, limit + 1, offset)
    const hasNext = page.length > limit
    const clients = page.slice(0, limit)
    return c.html(renderClientsList(chrome(c, "clients"), clients, limit, offset, hasNext))
  })

  app.get("/console/clients/new", async (c) =>
    c.html(
      renderClientForm(
        chrome(c, "clients"),
        null,
        issueCsrfToken(c),
        undefined,
        await listResources(c.env),
      ),
    ),
  )

  app.post("/console/clients", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect("/console/clients/new?flash=invalid")
    const values = readClientFormValues(form)
    const configuration = clientConfiguration(values)
    const issue = await clientConfigurationError(c.env, configuration, c.get("i18n"))
    if (issue !== undefined) return renderClientFormError(c, null, values, issue)
    if ((await getClientById(c.env, configuration.clientId)) !== null) {
      return renderClientFormError(c, null, values, {
        error: "That client ID is already registered.",
        field: "client_id",
        initialStep: 0,
      })
    }
    const secret = configuration.type === "confidential" ? generateClientSecret() : null
    await createClient(
      c.env,
      { ...configuration, requirePkce: true },
      secret === null ? null : await hashClientSecret(secret),
    )
    await recordAudit(c.env, {
      type: "admin.client.created",
      actorUserId: c.get("user")?.id ?? null,
      clientId: configuration.clientId,
      requestId: c.get("requestId"),
      success: true,
    })
    if (secret !== null) {
      return c.html(
        renderClientSecret(
          { ...chrome(c, "clients"), clearDraftKey: "keyforge:form:client:new" },
          configuration.clientId,
          secret,
        ),
      )
    }
    return c.redirect(
      withClearedDraft(
        `/console/clients/${encodeURIComponent(configuration.clientId)}?view=settings&flash=client_created`,
        "keyforge:form:client:new",
      ),
    )
  })

  app.get("/console/clients/:id", async (c) => {
    const client = await getClientById(c.env, c.req.param("id"))
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    const view = parseClientDetailView(c.req.query("view"))
    return c.html(
      renderClientDetail(
        chrome(c, "clients"),
        client,
        view,
        issueCsrfToken(c),
        view === "access" ? await listResources(c.env) : [],
      ),
    )
  })

  app.post("/console/clients/:id/settings", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/clients/${id}?view=settings&flash=invalid`)
    const current = await getClientById(c.env, id)
    if (current === null) return c.redirect("/console/clients?flash=not_found")
    const values = {
      ...clientValues(current),
      name: readFormField(form, "name"),
      redirectUris: readFormField(form, "redirect_uris"),
      postLogoutRedirectUris: readFormField(form, "post_logout_redirect_uris"),
    }
    const configuration = clientConfiguration(values)
    const issue = await clientConfigurationError(c.env, configuration, c.get("i18n"))
    if (issue !== undefined) return renderClientDetailError(c, current, "settings", values, issue)
    if (!(await updateClient(c.env, id, { ...configuration, requirePkce: true }))) {
      return c.redirect("/console/clients?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.client.updated",
      actorUserId: c.get("user")?.id ?? null,
      clientId: id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect(
      withClearedDraft(
        `/console/clients/${id}?view=settings&flash=client_updated`,
        `keyforge:form:client:${id}:settings`,
      ),
    )
  })

  app.post("/console/clients/:id/access", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/clients/${id}?view=access&flash=invalid`)
    const current = await getClientById(c.env, id)
    if (current === null) return c.redirect("/console/clients?flash=not_found")
    const values = {
      ...clientValues(current),
      allowedScopes: readFormField(form, "allowed_scopes"),
      allowedGrantTypes: readFormField(form, "allowed_grant_types"),
      allowedResources: form
        .getAll("allowed_resources")
        .flatMap((value) => (typeof value === "string" ? [value] : []))
        .join("\n"),
      defaultResource: readFormField(form, "default_resource"),
    }
    const configuration = clientConfiguration(values)
    const issue = await clientConfigurationError(c.env, configuration, c.get("i18n"))
    if (issue !== undefined) return renderClientDetailError(c, current, "access", values, issue)
    if (!(await updateClient(c.env, id, { ...configuration, requirePkce: true }))) {
      return c.redirect("/console/clients?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.client.updated",
      actorUserId: c.get("user")?.id ?? null,
      clientId: id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect(
      withClearedDraft(
        `/console/clients/${id}?view=access&flash=client_updated`,
        `keyforge:form:client:${id}:access`,
      ),
    )
  })

  app.post("/console/clients/:id/enable", (c) => setEnabled(c, true))

  app.get("/console/clients/:id/disable", async (c) => {
    const client = await getClientById(c.env, c.req.param("id"))
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    if (!client.enabled) {
      return c.redirect(`/console/clients/${client.clientId}?view=security&flash=not_found`)
    }
    return c.html(
      renderClientActionConfirmation(chrome(c, "clients"), client, issueCsrfToken(c), "disable"),
    )
  })

  app.post("/console/clients/:id/disable", (c) => setEnabled(c, false))

  app.get("/console/clients/:id/rotate-secret", async (c) => {
    const client = await getClientById(c.env, c.req.param("id"))
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    if (client.type !== "confidential") {
      return c.redirect(
        `/console/clients/${encodeURIComponent(client.clientId)}?view=security&flash=invalid`,
      )
    }
    return c.html(
      renderClientActionConfirmation(
        chrome(c, "clients"),
        client,
        issueCsrfToken(c),
        "rotate-secret",
      ),
    )
  })

  app.post("/console/clients/:id/rotate-secret", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/clients/${id}?view=security&flash=invalid`)
    const client = await getClientById(c.env, id)
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    if (client.type !== "confidential") {
      return c.redirect(`/console/clients/${id}?view=security&flash=invalid`)
    }
    if (readFormField(form, "confirmation") !== client.clientId) {
      return c.html(
        renderClientActionConfirmation(
          chrome(c, "clients"),
          client,
          issueCsrfToken(c),
          "rotate-secret",
          "The client ID did not match. No secret was changed.",
        ),
        400,
      )
    }
    const secret = generateClientSecret()
    await setClientSecretHash(c.env, id, await hashClientSecret(secret))
    await recordAudit(c.env, {
      type: "admin.client.secret_rotated",
      actorUserId: c.get("user")?.id ?? null,
      clientId: id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.html(renderClientSecret(chrome(c, "clients"), id, secret))
  })

  app.get("/console/clients/:id/delete", async (c) => {
    const client = await getClientById(c.env, c.req.param("id"))
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    return c.html(
      renderClientActionConfirmation(chrome(c, "clients"), client, issueCsrfToken(c), "delete"),
    )
  })

  app.post("/console/clients/:id/delete", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) return c.redirect(`/console/clients/${id}?view=security&flash=invalid`)
    const client = await getClientById(c.env, id)
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    if (readFormField(form, "confirmation") !== client.clientId) {
      return c.html(
        renderClientActionConfirmation(
          chrome(c, "clients"),
          client,
          issueCsrfToken(c),
          "delete",
          "The client ID did not match. Nothing was deleted.",
        ),
        400,
      )
    }
    if (!(await deleteClient(c.env, id))) return c.redirect("/console/clients?flash=not_found")
    await recordAudit(c.env, {
      type: "admin.client.deleted",
      actorUserId: c.get("user")?.id ?? null,
      clientId: id,
      requestId: c.get("requestId"),
      success: true,
      detail: "console deleted client",
    })
    return c.redirect("/console/clients?flash=client_deleted")
  })
}

async function setEnabled(c: Context<AppBindings>, enabled: boolean): Promise<Response> {
  const id = c.req.param("id")
  if (id === undefined) {
    return c.redirect("/console/clients?flash=not_found")
  }
  const form = await readVerifiedForm(c)
  if (form === null) {
    return c.redirect(`/console/clients/${id}?view=security&flash=invalid`)
  }
  if (!(await setClientEnabled(c.env, id, enabled))) {
    return c.redirect("/console/clients?flash=not_found")
  }
  await recordAudit(c.env, {
    type: enabled ? "admin.client.enabled" : "admin.client.disabled",
    actorUserId: c.get("user")?.id ?? null,
    clientId: id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.redirect(
    `/console/clients/${id}?view=security&flash=${enabled ? "client_enabled" : "client_disabled"}`,
  )
}
