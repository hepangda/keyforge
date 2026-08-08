# KeyForge — local demo relying party

A tiny **third-party application** that signs users in through the KeyForge
authorization server using **OpenID Connect** (authorization code + PKCE). It
is completely standalone — Node's built-in HTTP server plus [`jose`](https://github.com/panva/jose)
for id_token verification — and runs **entirely on your machine** against
`wrangler dev`.

```
examples/demo-app/
├── app.mjs               the relying party (discovery, PKCE, callback, RP logout)
├── seed-demo-client.sql  registers the "demo_local" OAuth client in the local D1
├── seed-test-admin.sql   creates the local demo-only administrator
├── selftest.mjs          one command that boots everything and drives the flow
└── package.json
```

The demo client (`demo_local`) is a **public** client with PKCE, redirecting to
`http://localhost:8788/callback`. It is only ever registered in the **local** D1
used by `wrangler dev`, never in production.
The seed also assigns `demo_local` to the seeded `employees` permission group.
The demo administrator is an `employees` member, so this explicit rule exercises
the same default-deny authorization boundary as every other user application.

## Prerequisites

- The auth server's dependencies installed in the repo root (`pnpm install`).
- This app's one dependency: `cd examples/demo-app && pnpm install`.

## Fastest path: the self-test

From `examples/demo-app/`:

```bash
pnpm selftest
```

This single command:

1. applies the local D1 migrations and registers the `demo_local` client;
2. starts the auth server (`wrangler dev` on `:17001`, with `ISSUER` overridden to
   `http://localhost:17001` so discovery/JWKS/tokens all point at localhost);
3. starts this demo app on `:8788`;
4. drives the **entire** flow over HTTP — `/login` → authorize → sign in as the
   local demo-only **`demo-admin` / `demo-admin-2026`** account → approve consent → callback with the code →
   token exchange → **id_token verified against the JWKS** — and asserts the user
   is authenticated;
5. tears both servers down.

Expect `✅ SELF-TEST PASSED`. Ports `17001` and `8788` must be free.

## Try it in a browser

Two terminals, from the repo root:

```bash
# terminal 1 — auth server, issuer pointed at localhost
pnpm exec wrangler d1 migrations apply keyforge --local
pnpm exec wrangler d1 execute keyforge --local --file=examples/demo-app/seed-test-admin.sql
pnpm exec wrangler d1 execute keyforge --local --file=examples/demo-app/seed-demo-client.sql
pnpm exec wrangler dev --var ISSUER:http://localhost:17001 --port 17001
```

```bash
# terminal 2 — the demo app
cd examples/demo-app && pnpm install && pnpm start
```

Open <http://localhost:8788>, click **Sign in with KeyForge**, log in with
`demo-admin` / `admin`, approve consent, and you'll land back on the demo showing your
verified `id_token` claims.

## Configuration

`app.mjs` reads these env vars (localhost defaults shown):

| Variable       | Default                          | Purpose                             |
| -------------- | -------------------------------- | ----------------------------------- |
| `AUTH_BASE`    | `http://localhost:17001`          | Auth server base URL (for discovery)|
| `PORT`         | `8788`                           | Port this demo listens on           |
| `CLIENT_ID`    | `demo_local`                     | Registered OAuth client id          |
| `REDIRECT_URI` | `http://localhost:8788/callback` | Must match the registered client    |
| `SCOPE`        | `openid profile email offline_access api.read` | Requested scopes      |
| `RESOURCE`     | `https://api.pangda.app`         | Access-token audience               |

## How it integrates (the OIDC dance)

1. **Discovery** — fetch `/.well-known/openid-configuration` for the
   authorization, token, and JWKS endpoints.
2. **`/login`** — generate a PKCE `code_verifier`/`code_challenge`, a random
   `state` and `nonce`, stash them, and redirect to the authorization endpoint.
3. **`/callback`** — validate `state`, POST the `code` + `code_verifier` to the
   token endpoint, then verify the returned `id_token` against the server's JWKS
   (checking `iss`, `aud`, and `nonce`) before establishing a local session.
