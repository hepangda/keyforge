import type { Context } from "hono"
import { Hono } from "hono"
import { SUPPORTED_SCOPES } from "../config"
import { listEnabledResourceScopes } from "../db/queries/resources"
import { buildDiscoveryMetadata } from "../oidc/discovery"
import { buildJwksDocument } from "../oidc/jwks"
import type { AppBindings } from "../types/app"

export const wellKnown = new Hono<AppBindings>()

async function discovery(c: Context<AppBindings>): Promise<Response> {
  const scopes = new Set<string>(SUPPORTED_SCOPES)
  for (const scope of await listEnabledResourceScopes(c.env)) scopes.add(scope)
  return c.json(buildDiscoveryMetadata(c.env.ISSUER, [...scopes]), 200, {
    "cache-control": "public, max-age=3600",
  })
}

wellKnown.get("/.well-known/openid-configuration", discovery)
wellKnown.get("/.well-known/oauth-authorization-server", discovery)

wellKnown.get("/.well-known/jwks.json", async (c) =>
  c.json(await buildJwksDocument(c.env), 200, {
    // Rotation stages a key for two minutes before use. Keep this cache bound
    // below that propagation window so a newly active kid is always known.
    "cache-control": "public, max-age=60, stale-while-revalidate=30",
  }),
)
