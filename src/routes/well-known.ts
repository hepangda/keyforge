import { Hono } from "hono"
import { buildDiscoveryMetadata } from "../oidc/discovery"
import { buildJwksDocument } from "../oidc/jwks"
import type { AppBindings } from "../types/app"

export const wellKnown = new Hono<AppBindings>()

wellKnown.get("/.well-known/openid-configuration", (c) =>
  c.json(buildDiscoveryMetadata(c.env.ISSUER), 200, {
    "cache-control": "public, max-age=3600",
  }),
)

wellKnown.get("/.well-known/jwks.json", async (c) =>
  c.json(await buildJwksDocument(c.env), 200, {
    // Rotation stages a key for two minutes before use. Keep this cache bound
    // below that propagation window so a newly active kid is always known.
    "cache-control": "public, max-age=60, stale-while-revalidate=30",
  }),
)
