// Verifies the real middleware ordering semantics of src/index.ts against Hono,
// running the actual library in Node. Not a test fixture — a probe.
const { Hono } = require("hono")
const { secureHeaders } = require("hono/secure-headers")
const { cors } = require("hono/cors")

const app = new Hono()

// Mirrors src/index.ts ordering.
app.use("/avatars/*", async (c, next) => {
  await next()
  c.header("cross-origin-resource-policy", "cross-origin")
})

app.use("/avatars/*", cors({ origin: "*", allowMethods: ["GET"] }))

app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: { defaultSrc: ["'none'"], imgSrc: ["'self'", "https:", "data:", "blob:"] },
    xFrameOptions: "DENY",
  }),
)

app.use("*", async (c, next) => {
  await next()
  const path = new URL(c.req.url).pathname
  if (!path.startsWith("/assets/") && !path.startsWith("/.well-known/") && !path.startsWith("/avatars/")) {
    c.header("cache-control", "no-store")
  }
})

app.get("/avatars/:key", (c) => {
  return new Response("IMAGEBYTES", {
    headers: {
      "content-type": "image/webp",
      "cache-control": "public, max-age=31536000, immutable",
      "content-security-policy": "default-src 'none'; sandbox",
      "x-content-type-options": "nosniff",
    },
  })
})

app.get("/", (c) => c.html("<html></html>"))

async function show(path, headers) {
  const res = await app.request(`http://localhost:17001${path}`, { headers })
  console.log(`\n--- ${path} (${res.status})`)
  for (const [k, v] of [...res.headers.entries()].sort()) console.log(`  ${k}: ${v}`)
}

;(async () => {
  await show("/avatars/abc.webp", { origin: "http://localhost:4321" })
  await show("/avatars/abc.webp", {})
  await show("/", {})
})()
