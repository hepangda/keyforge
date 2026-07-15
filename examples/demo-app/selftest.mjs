// One-command local self-test for the demo relying party.
//
// It seeds the LOCAL D1, starts the KeyForge authorization server (`wrangler dev`, with the
// issuer pointed at localhost) and this demo app, then drives the entire OpenID
// Connect login + callback flow over HTTP — signing in as the seeded admin, giving
// consent, receiving the code at the callback, exchanging it, and verifying the
// id_token — and asserts the user ends up authenticated. Everything runs locally.
//
//   node selftest.mjs      (or: pnpm selftest)

import { spawn, spawnSync } from "node:child_process"
import path from "node:path"
import { setTimeout as sleep } from "node:timers/promises"
import { fileURLToPath } from "node:url"

const DEMO_DIR = fileURLToPath(new URL(".", import.meta.url))
const ROOT = fileURLToPath(new URL("../../", import.meta.url))
const WRANGLER = path.join(ROOT, "node_modules", ".bin", "wrangler")
const SEED = path.join(DEMO_DIR, "seed-demo-client.sql")
const TEST_ADMIN_SEED = path.join(DEMO_DIR, "seed-test-admin.sql")

const AUTH_PORT = 8787
const DEMO_PORT = 8788
const AUTH_BASE = `http://localhost:${AUTH_PORT}`
const DEMO_BASE = `http://localhost:${DEMO_PORT}`

function assert(condition, message) {
  if (!condition) {
    throw new Error(`assertion failed: ${message}`)
  }
}

function step(message) {
  process.stdout.write(`\u2192 ${message}\n`)
}

function runSync(args, label) {
  step(label)
  const result = spawnSync(WRANGLER, args, { cwd: ROOT, encoding: "utf8" })
  if (result.status !== 0) {
    throw new Error(`\`wrangler ${args.join(" ")}\` failed:\n${result.stdout ?? ""}${result.stderr ?? ""}`)
  }
}

function absorb(jar, res) {
  for (const raw of res.headers.getSetCookie()) {
    const pair = raw.split(";", 1)[0]
    const eq = pair.indexOf("=")
    if (eq > 0) {
      jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim()
    }
  }
}

function cookie(jar) {
  return Object.entries(jar)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ")
}

async function waitFor(label, check, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      if (await check()) {
        return
      }
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${label}`)
    }
    await sleep(500)
  }
}

async function driveLoginFlow() {
  const authJar = {}

  step("demo /login builds the authorize request and redirects to the auth server")
  const started = await fetch(`${DEMO_BASE}/login`, { redirect: "manual" })
  const authorizeUrl = started.headers.get("location") ?? ""
  assert(authorizeUrl.includes("/oauth/authorize"), `expected authorize redirect, got ${authorizeUrl}`)

  step("authorize (signed out) bounces to the login page")
  const bounced = await fetch(authorizeUrl, { redirect: "manual" })
  const loginLocation = bounced.headers.get("location") ?? ""
  assert(loginLocation.includes("/login"), `expected login redirect, got ${loginLocation}`)
  const returnTo = new URL(loginLocation, AUTH_BASE).searchParams.get("return_to") ?? ""

  step("sign in as the local demo administrator")
  const loginPage = await fetch(`${AUTH_BASE}/login`, { redirect: "manual" })
  absorb(authJar, loginPage)
  const loginPost = await fetch(`${AUTH_BASE}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie: cookie(authJar) },
    body: new URLSearchParams({
      email: "demo-admin",
      password: "demo-admin-2026",
      csrf_token: authJar["__Host-keyforge_csrf"],
      return_to: returnTo,
    }),
    redirect: "manual",
  })
  absorb(authJar, loginPost)
  assert(authJar["__Host-keyforge_session"] !== undefined, "no session cookie after login")

  step("approve consent on the authorization request")
  const consent = await fetch(`${AUTH_BASE}${returnTo}`, {
    headers: { cookie: cookie(authJar) },
    redirect: "manual",
  })
  absorb(authJar, consent)
  assert(consent.status === 200, `expected consent page, got ${consent.status}`)
  const params = new URL(authorizeUrl).searchParams
  const decisionBody = new URLSearchParams()
  for (const key of [
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "resource",
  ]) {
    const value = params.get(key)
    if (value !== null) {
      decisionBody.set(key, value)
    }
  }
  decisionBody.set("decision", "approve")
  decisionBody.set("csrf_token", authJar["__Host-keyforge_csrf"])
  const decision = await fetch(`${AUTH_BASE}/oauth/authorize/decision`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie: cookie(authJar) },
    body: decisionBody,
    redirect: "manual",
  })
  const callbackUrl = decision.headers.get("location") ?? ""
  assert(callbackUrl.startsWith(`${DEMO_BASE}/callback`), `expected demo callback, got ${callbackUrl}`)

  step("the demo callback exchanges the code and verifies the id_token")
  const demoJar = {}
  const callback = await fetch(callbackUrl, { redirect: "manual" })
  absorb(demoJar, callback)
  assert(
    callback.status === 302,
    `callback failed (${callback.status}): ${await callback.text().catch(() => "")}`,
  )
  assert(demoJar["demo_session"] !== undefined, "demo did not establish a session")

  step("the demo home page shows the authenticated user")
  const home = await fetch(`${DEMO_BASE}/`, { headers: { cookie: cookie(demoJar) } })
  const html = await home.text()
  assert(home.status === 200, `home status ${home.status}`)
  assert(html.includes("Signed in"), "home page does not show a signed-in state")
  assert(html.includes("demo-admin"), "home page does not show the demo administrator")
}

async function main() {
  runSync(["d1", "migrations", "apply", "keyforge", "--local"], "apply local D1 migrations")
  runSync(
    ["d1", "execute", "keyforge", "--local", `--file=${TEST_ADMIN_SEED}`],
    "register the local demo administrator",
  )
  runSync(["d1", "execute", "keyforge", "--local", `--file=${SEED}`], "register the demo client")

  step(`start the auth server: wrangler dev on ${AUTH_BASE} (issuer overridden to localhost)`)
  const auth = spawn(
    WRANGLER,
    ["dev", "--var", `ISSUER:${AUTH_BASE}`, "--port", String(AUTH_PORT), "--ip", "127.0.0.1"],
    { cwd: ROOT, stdio: ["ignore", "ignore", "inherit"] },
  )

  step("start the demo relying party")
  const demo = spawn(process.execPath, ["app.mjs"], {
    cwd: DEMO_DIR,
    env: { ...process.env, AUTH_BASE, PORT: String(DEMO_PORT) },
    stdio: ["ignore", "ignore", "inherit"],
  })

  const shutdown = () => {
    auth.kill("SIGTERM")
    demo.kill("SIGTERM")
  }

  try {
    await waitFor(
      "auth server discovery (localhost issuer)",
      async () => {
        const res = await fetch(`${AUTH_BASE}/.well-known/openid-configuration`)
        if (!res.ok) {
          return false
        }
        const meta = await res.json()
        assert(
          meta.issuer === AUTH_BASE,
          `auth server issuer is ${meta.issuer}, expected ${AUTH_BASE} (the --var ISSUER override did not apply)`,
        )
        return true
      },
      90_000,
    )
    await waitFor("demo app", async () => (await fetch(`${DEMO_BASE}/`)).ok, 20_000)

    await driveLoginFlow()

    process.stdout.write("\n\u2705 SELF-TEST PASSED — the demo app completed a full OIDC login + callback locally.\n")
    shutdown()
    process.exit(0)
  } catch (err) {
    process.stdout.write(`\n\u274c SELF-TEST FAILED\n${err instanceof Error ? err.stack : String(err)}\n`)
    shutdown()
    process.exit(1)
  }
}

main()
