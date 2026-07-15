# KeyForge

KeyForge is a single-tenant OpenID Connect and OAuth 2.1 authorization server
for Cloudflare Workers. It provides browser SSO, CLI device authorization,
machine-to-machine credentials, account recovery, passwords, passkeys, and
an administrator console/API.

The browser UI and transactional emails support English, Simplified Chinese,
and Japanese. A saved language choice takes precedence; without one, KeyForge
uses the browser's `Accept-Language` preference and falls back to English. The
language picker can also be reset to follow the browser again.

The checked-in staging and production profiles currently target the Pangda
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
- D1-only audit retention: 90 days in staging and 365 days in production,
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

Open <http://localhost:8787/login> and sign in as `demo-admin` / `demo-admin-2026`. This
weak credential exists only in the explicit local demo seed and must never be
used outside a disposable development database.

To exercise the production-style bootstrap instead, do not apply the demo
administrator seed. Generate a token with `openssl rand -hex 32`, paste it into
`BOOTSTRAP_TOKEN` in `.dev.vars`, run `pnpm dev`, and use the same token from a
second terminal:

```bash
export BOOTSTRAP_TOKEN='paste-the-same-64-character-token-here'
curl -fsS http://localhost:8787/setup/bootstrap \
  -H 'content-type: application/json' \
  -H "x-bootstrap-token: $BOOTSTRAP_TOKEN" \
  --data '{"email":"owner@example.test","alias":"localowner","name":"Local Owner","password":"replace-with-a-unique-16+-character-password"}'
```

Then sign in with that email and password. Clear `BOOTSTRAP_TOKEN` from
`.dev.vars` and restart the Worker after bootstrap succeeds.

The local issuer is `http://localhost:8787`. Set `REQUEST_HASH_SECRET` to a random value when stable,
privacy-preserving request metadata hashes are useful during local testing.

The base Wrangler configuration is local/test-only. Remote commands must select
the `staging` or `production` environment explicitly.

```bash
pnpm check
pnpm test:coverage
pnpm demo:selftest
pnpm deploy:dry-run:staging
pnpm deploy:dry-run:production
```

Dry runs are build/configuration syntax checks and intentionally work while the
checked-in D1/KV IDs are placeholders. The remote migration and deploy scripts
run `validate-deploy-config.mjs` first and refuse placeholder IDs, shared
staging/production resources, or environment/issuer/route mismatches.

Tests create an isolated administrator fixture. Production migrations never
create credentials; provision the first production administrator with the
one-time `/setup/bootstrap` flow described in the operations runbook.

## Repository map

| Path | Purpose |
| --- | --- |
| `src/oauth`, `src/oidc`, `src/tokens` | OAuth/OIDC protocol and token handling |
| `src/auth`, `src/routes` | Authentication and HTTP routes |
| `src/i18n` | Locale negotiation and English/Chinese/Japanese message catalog |
| `src/operations` | Scheduled key rotation, cleanup, and audit retention deletion |
| `src/do` | Durable Object consistency boundaries |
| `migrations` | Ordered D1 schema and seed catalog |
| `test` | Workerd-backed unit and integration tests |
| `examples/demo-app` | Local OIDC relying-party self-test |

## Documentation

- [Operations, release, backup, and recovery](docs/operations.md)
- [Administrator API](docs/admin-api.md)
- [Local demo relying party](examples/demo-app/README.md)

Never commit `.dev.vars`, provider credentials, bootstrap tokens, client
secrets, exported D1 data, or signing-key backups.
