import type { Context, Hono } from "hono"
import {
  createClient,
  deleteClient,
  getClientById,
  listClients,
  setClientEnabled,
  setClientSecretHash,
  updateClient,
} from "../db/queries/clients"
import { type ClientConfiguration, validateClientConfiguration } from "../oauth/client-config"
import { isSafePostLogoutRedirectUri } from "../oauth/post-logout"
import { recordAudit } from "../security/audit"
import { generateClientSecret, hashClientSecret } from "../security/client-secret"
import { issueCsrfToken } from "../security/csrf"
import { isSafeOAuthRedirectUri } from "../security/redirect-uri"
import type { AppBindings } from "../types/app"
import type { ClientKind, ClientType, OAuthClient } from "../types/domain"
import { readFormField } from "../utils/form"
import {
  type ClientFormValues,
  renderClientActionConfirmation,
  renderClientForm,
  renderClientSecret,
  renderClientsList,
} from "../views/console/clients"
import { chrome, parseLines, readVerifiedForm } from "./shared"

function parseType(raw: string): ClientType {
  return raw === "confidential" ? "confidential" : "public"
}

function parseKind(raw: string): ClientKind {
  return raw === "device" || raw === "service" ? raw : "application"
}

function readClientFormValues(form: FormData, current?: OAuthClient): ClientFormValues {
  return {
    clientId: current?.clientId ?? readFormField(form, "client_id"),
    name: readFormField(form, "name"),
    type: current?.type ?? parseType(readFormField(form, "type")),
    clientKind: current?.clientKind ?? parseKind(readFormField(form, "client_kind")),
    redirectUris: readFormField(form, "redirect_uris"),
    postLogoutRedirectUris: readFormField(form, "post_logout_redirect_uris"),
    allowedScopes: readFormField(form, "allowed_scopes"),
    allowedGrantTypes: readFormField(form, "allowed_grant_types"),
    allowedResources: readFormField(form, "allowed_resources"),
    defaultResource: readFormField(form, "default_resource"),
  }
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

async function clientConfigurationError(
  env: Env,
  configuration: ClientConfiguration,
): Promise<string | undefined> {
  if (!configuration.redirectUris.every(isSafeOAuthRedirectUri)) {
    return "Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain native scheme, without credentials or fragments."
  }
  if (!configuration.postLogoutRedirectUris.every(isSafePostLogoutRedirectUri)) {
    return "Post-logout redirect URIs must use HTTPS or loopback HTTP, without credentials or fragments."
  }
  const validation = await validateClientConfiguration(env, configuration)
  return validation.ok ? undefined : `Configuration error: ${validation.reason}.`
}

function renderClientFormError(
  c: Context<AppBindings>,
  client: OAuthClient | null,
  values: ClientFormValues,
  error: string,
): Response {
  return c.html(
    renderClientForm(chrome(c, "clients"), client, issueCsrfToken(c), { values, error }),
    400,
  )
}

export function registerConsoleClients(app: Hono<AppBindings>): void {
  app.get("/console/clients", async (c) =>
    c.html(renderClientsList(chrome(c, "clients"), await listClients(c.env))),
  )

  app.get("/console/clients/new", (c) =>
    c.html(renderClientForm(chrome(c, "clients"), null, issueCsrfToken(c))),
  )

  app.post("/console/clients", async (c) => {
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect("/console/clients/new?flash=invalid")
    }
    const values = readClientFormValues(form)
    const configuration = clientConfiguration(values)
    const validationError = await clientConfigurationError(c.env, configuration)
    if (validationError !== undefined) {
      return renderClientFormError(c, null, values, validationError)
    }
    if ((await getClientById(c.env, configuration.clientId)) !== null) {
      return renderClientFormError(c, null, values, "That client ID is already registered.")
    }
    const secret = configuration.type === "confidential" ? generateClientSecret() : null
    await createClient(
      c.env,
      {
        ...configuration,
        requirePkce: true,
      },
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
      return c.html(renderClientSecret(chrome(c, "clients"), configuration.clientId, secret))
    }
    return c.redirect(
      `/console/clients/${encodeURIComponent(configuration.clientId)}?flash=client_created`,
    )
  })

  app.get("/console/clients/:id", async (c) => {
    const client = await getClientById(c.env, c.req.param("id"))
    if (client === null) {
      return c.redirect("/console/clients?flash=not_found")
    }
    return c.html(renderClientForm(chrome(c, "clients"), client, issueCsrfToken(c)))
  })

  app.post("/console/clients/:id", async (c) => {
    const id = c.req.param("id")
    const form = await readVerifiedForm(c)
    if (form === null) {
      return c.redirect(`/console/clients/${id}?flash=invalid`)
    }
    const current = await getClientById(c.env, id)
    if (current === null) return c.redirect("/console/clients?flash=not_found")
    const values = readClientFormValues(form, current)
    const configuration = clientConfiguration(values)
    const validationError = await clientConfigurationError(c.env, configuration)
    if (validationError !== undefined) {
      return renderClientFormError(c, current, values, validationError)
    }
    const patch = {
      name: configuration.name,
      redirectUris: configuration.redirectUris,
      postLogoutRedirectUris: configuration.postLogoutRedirectUris,
      allowedScopes: configuration.allowedScopes,
      allowedGrantTypes: configuration.allowedGrantTypes,
      allowedResources: configuration.allowedResources,
      defaultResource: configuration.defaultResource,
      requirePkce: true,
    }
    const ok = await updateClient(c.env, id, patch)
    if (!ok) {
      return c.redirect("/console/clients?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.client.updated",
      actorUserId: c.get("user")?.id ?? null,
      clientId: id,
      requestId: c.get("requestId"),
      success: true,
    })
    return c.redirect(`/console/clients/${id}?flash=client_updated`)
  })

  app.post("/console/clients/:id/enable", (c) => setEnabled(c, true))
  app.post("/console/clients/:id/disable", (c) => setEnabled(c, false))

  app.get("/console/clients/:id/rotate-secret", async (c) => {
    const client = await getClientById(c.env, c.req.param("id"))
    if (client === null) return c.redirect("/console/clients?flash=not_found")
    if (client.type !== "confidential") {
      return c.redirect(`/console/clients/${encodeURIComponent(client.clientId)}?flash=invalid`)
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
    if (form === null) {
      return c.redirect(`/console/clients/${id}?flash=invalid`)
    }
    const client = await getClientById(c.env, id)
    if (client === null) {
      return c.redirect("/console/clients?flash=not_found")
    }
    if (client.type !== "confidential") {
      return c.redirect(`/console/clients/${id}?flash=invalid`)
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
    if (form === null) {
      return c.redirect(`/console/clients/${id}?flash=invalid`)
    }
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
    if (!(await deleteClient(c.env, id))) {
      return c.redirect("/console/clients?flash=not_found")
    }
    await recordAudit(c.env, {
      type: "admin.client.updated",
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
    return c.redirect(`/console/clients/${id}?flash=invalid`)
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
    `/console/clients/${id}?flash=${enabled ? "client_enabled" : "client_disabled"}`,
  )
}
