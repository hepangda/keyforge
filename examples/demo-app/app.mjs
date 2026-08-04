// A minimal third-party OpenID Connect relying party (RP) that logs users in
// through the KeyForge authorization server. Standalone: Node's http server + `jose` only.
// Runs entirely locally against `wrangler dev`. See README.md.

import { createHash, randomBytes, randomUUID } from "node:crypto"
import { createServer } from "node:http"
import { createRemoteJWKSet, jwtVerify } from "jose"

const CONFIG = {
  authBase: process.env.AUTH_BASE ?? "http://localhost:17001",
  port: Number(process.env.PORT ?? 8788),
  clientId: process.env.CLIENT_ID ?? "demo_local",
  scope: process.env.SCOPE ?? "openid profile email offline_access api.read",
  resource: process.env.RESOURCE ?? "https://api.pangda.app",
}
CONFIG.redirectUri = process.env.REDIRECT_URI ?? `http://localhost:${CONFIG.port}/callback`

// Server-side stores keyed by the opaque values in the flow. In a real app these
// would be a database / signed cookies; a Map is enough for a local demo.
const pendingByState = new Map() // state -> { verifier, nonce }
const sessionsBySid = new Map() // sid -> { claims, tokens }

let discoveryPromise = null
let jwks = null

async function discovery() {
  if (discoveryPromise === null) {
    discoveryPromise = fetch(`${CONFIG.authBase}/.well-known/openid-configuration`).then((res) => {
      if (!res.ok) {
        throw new Error(`OIDC discovery failed: ${res.status}`)
      }
      return res.json()
    })
  }
  return discoveryPromise
}

function base64url(buffer) {
  return buffer.toString("base64url")
}

function makePkce() {
  const verifier = base64url(randomBytes(32))
  const challenge = base64url(createHash("sha256").update(verifier).digest())
  return { verifier, challenge }
}

function readCookies(req) {
  const out = {}
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=")
    if (eq > 0) {
      out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim())
    }
  }
  return out
}

function currentSession(req) {
  const sid = readCookies(req).demo_session
  return sid ? sessionsBySid.get(sid) : undefined
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
}

function page(body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Demo RP — KeyForge</title>
<style>
  body{font:16px/1.5 system-ui,-apple-system,sans-serif;max-width:660px;margin:3rem auto;padding:0 1.25rem;color:#18181b;background:#fafafa}
  h1{font-size:1.5rem;margin:0 0 .5rem}.muted{color:#71717a}
  a.btn,button.btn{display:inline-block;padding:.65rem 1.1rem;background:#18181b;color:#fff;border:0;border-radius:9px;text-decoration:none;font:inherit;cursor:pointer}
  a.btn.ghost{background:#fff;color:#18181b;border:1px solid #d4d4d8}
  pre{background:#f4f4f5;border:1px solid #e4e4e7;padding:1rem;border-radius:9px;overflow:auto;font-size:.85rem}
  .card{background:#fff;border:1px solid #e4e4e7;border-radius:14px;padding:1.5rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}
  code{background:#f4f4f5;padding:.1rem .35rem;border-radius:5px}
</style></head><body>${body}</body></html>`
}

function sendHtml(res, status, body) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" }).end(page(body))
}

function homeView(req, res) {
  const session = currentSession(req)
  if (session === undefined) {
    sendHtml(
      res,
      200,
      `<div class="card"><h1>Demo Relying Party</h1>
      <p class="muted">A third-party application that signs users in through <strong>KeyForge</strong> using OpenID Connect (authorization code + PKCE).</p>
      <p><a class="btn" href="/login">Sign in with KeyForge</a></p></div>`,
    )
    return
  }
  const claims = session.claims
  const name = claims.name ?? claims.email ?? claims.sub
  sendHtml(
    res,
    200,
    `<div class="card"><h1>Signed in \u2713</h1>
    <p class="muted">You authenticated through KeyForge. This app verified your <code>id_token</code> against the server's JWKS.</p>
    <p><strong>${escapeHtml(name)}</strong>${claims.email ? ` &middot; <code>${escapeHtml(claims.email)}</code>` : ""}</p>
    <h3>Verified id_token claims</h3>
    <pre>${escapeHtml(JSON.stringify(claims, null, 2))}</pre>
    <form method="post" action="/logout"><button class="btn ghost" type="submit">Sign out</button></form></div>`,
  )
}

async function loginView(_req, res) {
  const meta = await discovery()
  const { verifier, challenge } = makePkce()
  const state = base64url(randomBytes(16))
  const nonce = base64url(randomBytes(16))
  pendingByState.set(state, { verifier, nonce })

  const authorize = new URL(meta.authorization_endpoint)
  const params = {
    response_type: "code",
    client_id: CONFIG.clientId,
    redirect_uri: CONFIG.redirectUri,
    scope: CONFIG.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: CONFIG.resource,
  }
  for (const [key, value] of Object.entries(params)) {
    authorize.searchParams.set(key, value)
  }
  res.writeHead(302, { location: authorize.toString() }).end()
}

async function callbackView(req, res, url) {
  const error = url.searchParams.get("error")
  if (error !== null) {
    sendHtml(
      res,
      400,
      `<div class="card"><h1>Authorization failed</h1>
      <p><code>${escapeHtml(error)}</code>: ${escapeHtml(url.searchParams.get("error_description") ?? "")}</p>
      <p><a class="btn ghost" href="/">Back</a></p></div>`,
    )
    return
  }

  const code = url.searchParams.get("code")
  const state = url.searchParams.get("state")
  const pending = state === null ? undefined : pendingByState.get(state)
  if (code === null || pending === undefined) {
    sendHtml(res, 400, `<div class="card"><h1>Invalid callback</h1><p>Unknown or missing state.</p></div>`)
    return
  }
  pendingByState.delete(state)

  const meta = await discovery()
  const tokenRes = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: CONFIG.redirectUri,
      code_verifier: pending.verifier,
      client_id: CONFIG.clientId,
    }),
  })
  if (!tokenRes.ok) {
    sendHtml(
      res,
      502,
      `<div class="card"><h1>Token exchange failed</h1><pre>${escapeHtml(`${tokenRes.status} ${await tokenRes.text()}`)}</pre></div>`,
    )
    return
  }
  const tokens = await tokenRes.json()

  if (jwks === null) {
    jwks = createRemoteJWKSet(new URL(meta.jwks_uri))
  }
  const { payload } = await jwtVerify(tokens.id_token, jwks, {
    issuer: meta.issuer,
    audience: CONFIG.clientId,
  })
  if (payload.nonce !== pending.nonce) {
    sendHtml(res, 400, `<div class="card"><h1>Replay check failed</h1><p>id_token nonce mismatch.</p></div>`)
    return
  }

  const sid = randomUUID()
  sessionsBySid.set(sid, { claims: payload, tokens })
  res
    .writeHead(302, {
      location: "/",
      "set-cookie": `demo_session=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=3600`,
    })
    .end()
}

async function logoutView(req, res) {
  const sid = readCookies(req).demo_session
  const session = sid === undefined ? undefined : sessionsBySid.get(sid)
  if (sid !== undefined) {
    sessionsBySid.delete(sid)
  }
  const metadata = await discovery()
  const logout = new URL(metadata.end_session_endpoint)
  logout.searchParams.set("client_id", CONFIG.clientId)
  logout.searchParams.set("post_logout_redirect_uri", `http://localhost:${CONFIG.port}/`)
  if (session?.tokens.id_token) {
    logout.searchParams.set("id_token_hint", session.tokens.id_token)
  }
  res
    .writeHead(302, {
      location: logout.toString(),
      "set-cookie": "demo_session=; Path=/; Max-Age=0",
    })
    .end()
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${CONFIG.port}`)
  try {
    if (req.method === "GET" && url.pathname === "/") {
      return homeView(req, res)
    }
    if (req.method === "GET" && url.pathname === "/login") {
      return await loginView(req, res)
    }
    if (req.method === "GET" && url.pathname === "/callback") {
      return await callbackView(req, res, url)
    }
    if (req.method === "POST" && url.pathname === "/logout") {
      return await logoutView(req, res)
    }
    res.writeHead(404, { "content-type": "text/plain" }).end("Not found")
  } catch (err) {
    console.error("demo-rp error", err)
    sendHtml(res, 500, `<div class="card"><h1>Server error</h1><pre>${escapeHtml(String(err))}</pre></div>`)
  }
})

server.listen(CONFIG.port, () => {
  process.stdout.write(`Demo RP listening on http://localhost:${CONFIG.port}  (auth: ${CONFIG.authBase})\n`)
})
