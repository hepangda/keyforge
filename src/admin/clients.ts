import type { Context, Hono } from "hono"
import * as z from "zod"
import {
  createClient,
  deleteClient,
  getClientById,
  listClients,
  setClientEnabled,
  setClientSecretHash,
  updateClient,
} from "../db/queries/clients"
import { validateClientConfiguration } from "../oauth/client-config"
import { isSafePostLogoutRedirectUri } from "../oauth/post-logout"
import { recordAudit } from "../security/audit"
import { generateClientSecret, hashClientSecret } from "../security/client-secret"
import { isSafeOAuthRedirectUri } from "../security/redirect-uri"
import type { AppBindings } from "../types/app"
import type { OAuthClient } from "../types/domain"
import { readJsonBody } from "../utils/http"

const postLogoutRedirectUriSchema = z
  .string()
  .refine(isSafePostLogoutRedirectUri, "Unsafe post-logout redirect URI")
const redirectUriSchema = z.string().refine(isSafeOAuthRedirectUri, "Unsafe OAuth redirect URI")

const createSchema = z.object({
  client_id: z.string().min(1),
  name: z.string().min(1),
  type: z.enum(["public", "confidential"]),
  client_kind: z.enum(["application", "device", "service"]),
  redirect_uris: z.array(redirectUriSchema).default([]),
  post_logout_redirect_uris: z.array(postLogoutRedirectUriSchema).default([]),
  allowed_scopes: z.array(z.string()).default([]),
  allowed_grant_types: z.array(z.string()).default([]),
  allowed_resources: z.array(z.string()).default([]),
  default_resource: z.string().nullable().default(null),
  require_pkce: z.literal(true).default(true),
})

const patchSchema = z.object({
  name: z.string().optional(),
  redirect_uris: z.array(redirectUriSchema).optional(),
  post_logout_redirect_uris: z.array(postLogoutRedirectUriSchema).optional(),
  allowed_scopes: z.array(z.string()).optional(),
  allowed_grant_types: z.array(z.string()).optional(),
  allowed_resources: z.array(z.string()).optional(),
  default_resource: z.string().nullable().optional(),
  require_pkce: z.literal(true).optional(),
})

type MutableClientPatch = {
  name?: string
  redirectUris?: string[]
  postLogoutRedirectUris?: string[]
  allowedScopes?: string[]
  allowedGrantTypes?: string[]
  allowedResources?: string[]
  defaultResource?: string | null
  requirePkce?: boolean
}

function serializeClient(client: OAuthClient): Record<string, unknown> {
  return {
    client_id: client.clientId,
    name: client.name,
    type: client.type,
    client_kind: client.clientKind,
    redirect_uris: client.redirectUris,
    post_logout_redirect_uris: client.postLogoutRedirectUris,
    allowed_scopes: client.allowedScopes,
    allowed_grant_types: client.allowedGrantTypes,
    allowed_resources: client.allowedResources,
    default_resource: client.defaultResource,
    require_pkce: client.requirePkce,
    enabled: client.enabled,
    has_secret: client.clientSecretHash !== null,
  }
}

export function registerAdminClients(app: Hono<AppBindings>): void {
  app.get("/admin/clients", async (c) =>
    c.json({ clients: (await listClients(c.env)).map(serializeClient) }),
  )

  app.post("/admin/clients", async (c) => {
    const parsed = createSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const body = parsed.data
    const configuration = {
      clientId: body.client_id,
      name: body.name,
      type: body.type,
      clientKind: body.client_kind,
      redirectUris: body.redirect_uris,
      postLogoutRedirectUris: body.post_logout_redirect_uris,
      allowedScopes: body.allowed_scopes,
      allowedGrantTypes: body.allowed_grant_types,
      allowedResources: body.allowed_resources,
      defaultResource: body.default_resource,
    }
    const validation = await validateClientConfiguration(c.env, configuration)
    if (!validation.ok) {
      return c.json(
        { error: "invalid_client_configuration", error_description: validation.reason },
        400,
      )
    }
    if ((await getClientById(c.env, body.client_id)) !== null) {
      return c.json({ error: "conflict" }, 409)
    }
    const secret = body.type === "confidential" ? generateClientSecret() : null
    await createClient(
      c.env,
      {
        ...configuration,
        requirePkce: body.require_pkce,
      },
      secret === null ? null : await hashClientSecret(secret),
    )
    await recordAudit(c.env, {
      type: "admin.client.created",
      actorUserId: c.get("user")?.id ?? null,
      clientId: body.client_id,
      requestId: c.get("requestId"),
      success: true,
    })
    const created = await getClientById(c.env, body.client_id)
    const view = created === null ? {} : serializeClient(created)
    return c.json(secret === null ? view : { ...view, client_secret: secret }, 201)
  })

  app.patch("/admin/clients/:id", async (c) => {
    const parsed = patchSchema.safeParse(await readJsonBody(c))
    if (!parsed.success) {
      return c.json({ error: "invalid_request" }, 400)
    }
    const body = parsed.data
    const id = c.req.param("id")
    const current = await getClientById(c.env, id)
    if (current === null) return c.json({ error: "not_found" }, 404)
    const patch: MutableClientPatch = {}
    if (body.name !== undefined) patch.name = body.name
    if (body.redirect_uris !== undefined) patch.redirectUris = body.redirect_uris
    if (body.post_logout_redirect_uris !== undefined) {
      patch.postLogoutRedirectUris = body.post_logout_redirect_uris
    }
    if (body.allowed_scopes !== undefined) patch.allowedScopes = body.allowed_scopes
    if (body.allowed_grant_types !== undefined) patch.allowedGrantTypes = body.allowed_grant_types
    if (body.allowed_resources !== undefined) patch.allowedResources = body.allowed_resources
    if (body.default_resource !== undefined) patch.defaultResource = body.default_resource
    if (body.require_pkce !== undefined) patch.requirePkce = true

    const validation = await validateClientConfiguration(c.env, {
      clientId: current.clientId,
      name: patch.name ?? current.name,
      type: current.type,
      clientKind: current.clientKind,
      redirectUris: patch.redirectUris ?? current.redirectUris,
      postLogoutRedirectUris: patch.postLogoutRedirectUris ?? current.postLogoutRedirectUris,
      allowedScopes: patch.allowedScopes ?? current.allowedScopes,
      allowedGrantTypes: patch.allowedGrantTypes ?? current.allowedGrantTypes,
      allowedResources: patch.allowedResources ?? current.allowedResources,
      defaultResource:
        patch.defaultResource === undefined ? current.defaultResource : patch.defaultResource,
    })
    if (!validation.ok) {
      return c.json(
        { error: "invalid_client_configuration", error_description: validation.reason },
        400,
      )
    }
    if (!(await updateClient(c.env, id, patch))) {
      return c.json({ error: "not_found" }, 404)
    }
    await recordAudit(c.env, {
      type: "admin.client.updated",
      actorUserId: c.get("user")?.id ?? null,
      clientId: id,
      requestId: c.get("requestId"),
      success: true,
    })
    const updated = await getClientById(c.env, id)
    return c.json(updated === null ? {} : serializeClient(updated))
  })

  app.delete("/admin/clients/:id", async (c) => {
    if (!(await deleteClient(c.env, c.req.param("id")))) {
      return c.json({ error: "not_found" }, 404)
    }
    await recordAudit(c.env, {
      type: "admin.client.deleted",
      actorUserId: c.get("user")?.id ?? null,
      clientId: c.req.param("id"),
      requestId: c.get("requestId"),
      success: true,
      detail: "client deleted",
    })
    return c.json({ deleted: true })
  })

  app.post("/admin/clients/:id/rotate-secret", async (c) => {
    const id = c.req.param("id")
    const client = await getClientById(c.env, id)
    if (client === null) {
      return c.json({ error: "not_found" }, 404)
    }
    if (client.type !== "confidential") {
      return c.json(
        { error: "invalid_request", error_description: "Only confidential clients have secrets" },
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
    return c.json({ client_id: id, client_secret: secret })
  })

  app.post("/admin/clients/:id/disable", (c) => setEnabled(c, c.req.param("id"), false))
  app.post("/admin/clients/:id/enable", (c) => setEnabled(c, c.req.param("id"), true))
}

async function setEnabled(
  c: Context<AppBindings>,
  id: string,
  enabled: boolean,
): Promise<Response> {
  if (!(await setClientEnabled(c.env, id, enabled))) {
    return c.json({ error: "not_found" }, 404)
  }
  await recordAudit(c.env, {
    type: enabled ? "admin.client.enabled" : "admin.client.disabled",
    actorUserId: c.get("user")?.id ?? null,
    clientId: id,
    requestId: c.get("requestId"),
    success: true,
  })
  return c.json({ client_id: id, enabled })
}
