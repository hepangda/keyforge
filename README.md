# KeyForge

KeyForge is a single-tenant OpenID Connect and OAuth 2.1 authorization server
for Cloudflare Workers. It provides browser SSO, CLI device authorization,
machine-to-machine credentials, account recovery, passwords, passkeys, and
an administrator console/API.

The browser UI and transactional emails support English, Simplified Chinese,
and Japanese. A saved language choice takes precedence; without one, KeyForge
uses the browser's `Accept-Language` preference and falls back to English. The
language picker can also be reset to follow the browser again.

The checked-in dev and production profiles currently target the Pangda
tenant. Its `pangda.app` issuer/resource URIs and seeded Pangda client catalog
are deployment data; KeyForge is the project and runtime brand.

## Architecture

- Hono + TypeScript on Cloudflare Workers
- D1 for users, clients, grants, sessions, refresh-token mirrors, actor-attributed
  audit logs, and the strongly consistent signing-key authority
- Durable Objects for one-time codes, challenges, rate limits, and refresh-token families
- KV only for local email capture and one-time migration of pre-D1 signing-key
  state; cleanup is durably retried and readiness stays red until every legacy
  private-key copy is confirmed deleted
- Separate Queues for asynchronous audit ingestion and transactional email
  delivery with provider-idempotent retries and dead-letter isolation
- D1-only audit retention: 90 days in dev and 365 days in production,
  followed by bounded direct deletion with no archive copy

The Worker publishes standard discovery metadata at
`/.well-known/openid-configuration` and implements authorization code + PKCE,
refresh token rotation, device code, and client credentials grants. Interactive
authorization supports OIDC `prompt=none|login|consent` and `max_age`; relying
parties can discover `/oauth/end_session` for validated RP-Initiated Logout.

## Local development

Requirements: Node.js 20–26 and pnpm 10.

```bash
corepack enable
pnpm install --frozen-lockfile
cp .dev.vars.example .dev.vars
pnpm db:migrate:local
```

For a disposable local database, seed the demo-only administrator and start the
Worker:

```bash
pnpm exec wrangler d1 execute keyforge --local --file=examples/demo-app/seed-test-admin.sql
pnpm dev
```

Open <http://localhost:17001/login> and sign in as `demo-admin` / `demo-admin-2026`. This
weak credential exists only in the explicit local demo seed and must never be
used outside a disposable development database.

To run locally with YOLO mode on, use `pnpm dev:yolo`. Plain `pnpm dev` loads
the top-level `[vars]`, where `ENVIRONMENT` is `local`, and YOLO mode is only
ever honoured for `dev` — so the switch stays off. `dev:yolo` overrides both
`ENVIRONMENT` and `YOLO_MODE` for that one process. It also relaxes the strict
remote-config checks that `ENVIRONMENT=dev` would otherwise impose, so local
`console` email and absent secrets still work. With it on, any existing account
signs in when the password repeats the login name (`demo-admin` / `demo-admin`).

To exercise the production-style bootstrap instead, do not apply the demo
administrator seed. Generate a token with `openssl rand -hex 32`, paste it into
`BOOTSTRAP_TOKEN` in `.dev.vars`, run `pnpm dev`, and use the same token from a
second terminal:

```bash
export BOOTSTRAP_TOKEN='paste-the-same-64-character-token-here'
curl -fsS http://localhost:17001/setup/bootstrap \
  -H 'content-type: application/json' \
  -H "x-bootstrap-token: $BOOTSTRAP_TOKEN" \
  --data '{"email":"owner@example.test","alias":"localowner","name":"Local Owner","password":"replace-with-a-unique-16+-character-password"}'
```

Then sign in with that email and password. Clear `BOOTSTRAP_TOKEN` from
`.dev.vars` and restart the Worker after bootstrap succeeds.

The local issuer is `http://localhost:17001`. Set `REQUEST_HASH_SECRET` to a random value when stable,
privacy-preserving request metadata hashes are useful during local testing.

The base Wrangler configuration is local/test-only. Remote commands must select
the `dev` or `production` environment explicitly.

The `dev` environment additionally supports a `YOLO_MODE` switch. When it is
`"true"`, KeyForge performs no substantive validation and approves every
request — no rate limits, CSRF, PKCE, redirect-URI registration, client-secret,
consent, scope, administrator, or password checks. It is honoured only when
`ENVIRONMENT` is exactly `dev`, so `local`, `test`, and `production` ignore it,
and the deployment validator refuses a production profile that declares it at
all. See [the operations runbook](docs/operations.md#yolo-mode-dev-only).

```bash
pnpm check
pnpm test:coverage
pnpm demo:selftest
pnpm deploy:dry-run:dev
pnpm deploy:dry-run:production
```

For an existing remote installation, the complete migration, deployment, and
post-deploy verification flow is available as one command after loading the
target readiness credential from the monitoring secret manager:

```bash
export KEYFORGE_DEV_READINESS_TOKEN='load-from-secret-manager'
pnpm release:dev
unset KEYFORGE_DEV_READINESS_TOKEN

export KEYFORGE_PRODUCTION_READINESS_TOKEN='load-from-secret-manager'
pnpm release:production
unset KEYFORGE_PRODUCTION_READINESS_TOKEN
```

Production requires a clean `main` worktree and an explicit confirmation. See
[the operations runbook](docs/operations.md#one-command-release) for CI usage,
release gates, backups, and failure handling.

Dry runs are build/configuration syntax checks and intentionally work while the
checked-in D1/KV IDs are placeholders. The remote migration and deploy scripts
run `validate-deploy-config.mjs` first and refuse placeholder IDs, shared
dev/production resources, or environment/issuer/route mismatches.

Tests create an isolated administrator fixture. Production migrations never
create credentials; provision the first production administrator with the
one-time `/setup/bootstrap` flow described in the operations runbook.

## Repository map

| Path | Purpose |
| --- | --- |
| `src/oauth`, `src/oidc`, `src/tokens` | OAuth/OIDC protocol and token handling |
| `src/auth`, `src/routes` | Authentication and HTTP routes |
| `src/i18n` | Locale negotiation and English/Chinese/Japanese message catalog |
| `src/media` | Avatar validation and R2-backed storage |
| `src/operations` | Scheduled key rotation, cleanup, and audit retention deletion |
| `src/do` | Durable Object consistency boundaries |
| `migrations` | Ordered D1 schema and seed catalog |
| `test` | Workerd-backed unit and integration tests |
| `examples/demo-app` | Local OIDC relying-party self-test |

## Documentation

- [Operations, release, backup, and recovery](docs/operations.md)
- [Administrator API](docs/admin-api.md)
- [Avatars](docs/avatars.md)
- [Local demo relying party](examples/demo-app/README.md)

Never commit `.dev.vars`, provider credentials, bootstrap tokens, client
secrets, exported D1 data, or signing-key backups.
