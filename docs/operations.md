# Operations runbook

This runbook covers provisioning, releases, scheduled maintenance, backup,
rollback, and alerting. Commands assume Wrangler 4 from this repository.

## Environment model

`wrangler.toml` defines three isolated binding sets:

| Configuration | Remote target | Issuer |
| --- | --- | --- |
| top-level | local development and tests only | `http://localhost:8787` |
| `staging` | `keyforge-staging` | `https://auth-staging.pangda.app` |
| `production` | `keyforge` | `https://auth.pangda.app` |

D1, KV, both Queue/DLQ pairs, and R2 resources are separate in staging and production.
The checked-in UUIDs are deliberate placeholders. Resource identifiers are not
secrets and should replace the matching placeholders in `wrangler.toml` after
provisioning so every operator and CI validates and deploys the same bindings.

Remote migration and deploy package scripts run a fail-closed preflight. It
rejects placeholder or shared D1/KV IDs, missing bindings, mismatched Queue
producer/consumer names, non-hourly maintenance, and any disagreement between
the selected environment, issuer, Worker, and custom-domain route. A Wrangler
dry run remains available separately because it validates the build and TOML
shape without proving that provisioned resources exist.

Create one complete resource set per environment:

```bash
pnpm exec wrangler d1 create keyforge_staging
pnpm exec wrangler kv namespace create KV --env staging
pnpm exec wrangler queues create keyforge-audit-staging
pnpm exec wrangler queues create keyforge-audit-staging-dlq
pnpm exec wrangler queues create keyforge-email-staging
pnpm exec wrangler queues create keyforge-email-staging-dlq
pnpm exec wrangler r2 bucket create keyforge-archive-staging
```

Repeat with production names, then replace only the matching environment's D1
and KV placeholder IDs. Audit/email Queue and bucket names are already explicit.

## Secrets and first administrator

Set secrets independently in each environment. Remote readiness requires a
random `REQUEST_HASH_SECRET` and a dedicated `READINESS_PROBE_TOKEN`, each at
least 32 characters. Generate a different readiness token for staging and
production, store the matching copy in the monitoring system's secret manager,
and do not reuse an OAuth client secret. Because remote email uses Resend, it
also requires both `RESEND_API_KEY` and `EMAIL_FROM`. Social providers are
optional, but each configured provider requires both its client ID and client
secret.

```bash
pnpm exec wrangler secret put RESEND_API_KEY --env staging
pnpm exec wrangler secret put EMAIL_FROM --env staging
pnpm exec wrangler secret put REQUEST_HASH_SECRET --env staging
READINESS_PROBE_TOKEN="$(openssl rand -hex 32)"
printf '%s' "$READINESS_PROBE_TOKEN" | pnpm exec wrangler secret put READINESS_PROBE_TOKEN --env staging
# Store this value in the staging monitor's secret manager, then unset it.
unset READINESS_PROBE_TOKEN
pnpm exec wrangler secret put GITHUB_CLIENT_ID --env staging
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET --env staging
pnpm exec wrangler secret put GOOGLE_CLIENT_ID --env staging
pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET --env staging
```

Repeat for production, generating a new `READINESS_PROBE_TOKEN`. Keep
`ALLOW_SELF_SIGNUP="false"` unless the tenant has
an explicit open-registration policy; the value must be the literal `true` or
`false`. Secret values never belong in `wrangler.toml`, `.dev.vars.example`,
logs, support tickets, or D1 exports shared with developers.

Migrations contain no password or administrator. Bootstrap staging and
production separately, with a new random token for each environment. Put the
secret before that environment's first deployment; call the endpoint only
after its migrations and Worker deployment have completed.

For staging:

```bash
BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
printf '%s' "$BOOTSTRAP_TOKEN" | pnpm exec wrangler secret put BOOTSTRAP_TOKEN --env staging

# Run pnpm db:migrate:staging and pnpm deploy:staging before this request.
curl -fsS https://auth-staging.pangda.app/setup/bootstrap \
  -H 'content-type: application/json' \
  -H "x-bootstrap-token: $BOOTSTRAP_TOKEN" \
  --data '{"email":"stage-owner@pangda.app","name":"Staging Owner","password":"replace-with-a-unique-16+-character-password"}'

pnpm exec wrangler secret delete BOOTSTRAP_TOKEN --env staging
unset BOOTSTRAP_TOKEN
```

For production, generate a different token and repeat the complete sequence:

```bash
BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
printf '%s' "$BOOTSTRAP_TOKEN" | pnpm exec wrangler secret put BOOTSTRAP_TOKEN --env production

# Run pnpm db:migrate:production and pnpm deploy:production before this request.
curl -fsS https://auth.pangda.app/setup/bootstrap \
  -H 'content-type: application/json' \
  -H "x-bootstrap-token: $BOOTSTRAP_TOKEN" \
  --data '{"email":"owner@pangda.app","name":"Initial Owner","password":"replace-with-a-unique-16+-character-password"}'

pnpm exec wrangler secret delete BOOTSTRAP_TOKEN --env production
unset BOOTSTRAP_TOKEN
```

The endpoint returns `409` once an administrator exists. Never leave either
bootstrap secret configured after the first administrator has been verified.

## Release procedure

1. Run local gates:

   ```bash
   pnpm install --frozen-lockfile
   pnpm check
   pnpm test:coverage
   pnpm demo:selftest
   pnpm audit --audit-level moderate
   pnpm secrets:scan
   pnpm deploy:dry-run:staging
   pnpm deploy:dry-run:production
   ```

2. Export D1 before applying a schema migration:

   ```bash
   pnpm exec wrangler d1 export keyforge_staging --env staging --remote \
     --output backups/keyforge_staging-pre-release.sql
   ```

   Store exports encrypted outside the repository and delete the local copy.

3. Apply and validate staging:

   ```bash
   pnpm db:migrate:staging
   pnpm deploy:staging
   curl -fsS https://auth-staging.pangda.app/health/ready \
     -H "Authorization: Bearer $READINESS_PROBE_TOKEN"
   ```

4. Exercise discovery, JWKS, login, authorization code + PKCE, refresh, email,
   and an administrator mutation in staging.

5. Export production D1, apply production migrations, then deploy:

   ```bash
   pnpm exec wrangler d1 export keyforge --env production --remote \
     --output backups/keyforge-pre-release.sql
   pnpm db:migrate:production
   pnpm deploy:production
   curl -fsS https://auth.pangda.app/health/ready \
     -H "Authorization: Bearer $READINESS_PROBE_TOKEN"
   ```

Do not deploy if readiness is not `200` with every check marked `ok`.

`pnpm db:migrate:*` and `pnpm deploy:*` (except `deploy:dry-run:*`) refuse to
continue until real, isolated remote resource IDs are present. This is expected
on an unprovisioned checkout; never bypass it by copying production IDs into
staging or by invoking raw Wrangler commands as a release shortcut.

## Scheduled maintenance and retention

The `15 * * * *` UTC cron runs hourly at minute 15, acquires a D1 lease, and
then performs bounded work so an accumulated audit backlog drains over
successive invocations:

- rotates the active RS256 signing key when it is seven days old;
- retains retired public keys through the token verification grace window;
- archives D1 audit rows older than 90 days to deterministic R2 JSON objects;
- removes archived R2 objects after 2,555 days (seven years);
- removes expired/revoked sessions, refresh tokens, device sessions, grant
  history, and one-time token rows after the configured terminal retention
  window (14 days in staging and 30 days in production).

Staging uses shorter audit and archive retention. All values are bounded runtime
variables in `wrangler.toml`. Archive upload completes before the corresponding
D1 rows are deleted. A retry overwrites the same deterministic object key.

Successful runs log `maintenance.completed`, including the remaining eligible
audit backlog and oldest eligible row. A thrown error leaves source rows in D1
and lets the next hourly invocation retry; the lease expires after 15 minutes
if an isolate terminates unexpectedly. Do not change the cron back to daily:
the bounded D1 query budget relies on frequent small batches.

### Refresh-family safety bounds

Refresh-token families have three static, fail-closed limits in
`REFRESH_TOKEN_POLICY`:

- after the first rotation, successful rotations must be at least 10 seconds
  apart; an earlier request returns `429 temporarily_unavailable` with
  `Retry-After` and leaves the current refresh token usable;
- a family permits at most 10,000 successful rotations. The next refresh burns
  the Durable Object family, marks its D1 mirror revoked, and returns
  `invalid_grant`; the user must complete authorization again;
- one user/client pair retains at most 20 active families. Creating another
  family atomically keeps the new family and revokes the oldest excess rows by
  `created_at, id`; those D1 revocations are then mirrored to the corresponding
  Durable Objects. Other clients and other users have independent limits.

Revoked D1 rows remain subject to the normal terminal-retention maintenance
window. Alert on sustained refresh `429` responses, generation-limit messages,
or repeated `refresh_family.do_revocation_failed` logs. D1 is authoritative if
a DO mirror retry fails, so do not clear `revoked_at` manually. Fix the DO
binding/outage, confirm later revocation synchronization, and have affected
users authorize again. Raising these constants increases Durable Object storage
or the number of live credentials and requires a reviewed code release; they are
not runtime tuning controls.

## Readiness and alerting

`GET /health` is liveness only. Local development leaves `GET /health/ready`
open, while staging and production require
`Authorization: Bearer <READINESS_PROBE_TOKEN>` before any dependency is
probed. A missing remote token fails closed with `503`; a missing or incorrect
request credential returns `401`. The authenticated readiness endpoint verifies all required
bindings; strict runtime values; Resend and request-hash secrets; the schema
through migration 0012, including required tables, actor/subject audit columns,
actor lookup indexes, and bounded-cleanup indexes; the identity uniqueness
index; the administrator seed catalog; the
D1-authoritative signing key, published JWKS, and completed legacy-KV cleanup;
R2; both Queue metrics; and a Durable Object RPC. It returns no secret values
or failure details. Alert on:

- readiness failing twice within two minutes;
- Worker 5xx rate or `/oauth/token` latency/error rate exceeding the service SLO;
- audit or transactional-email Queue backlog age, DLQ messages, or repeated
  queue-consumer retries;
- no `maintenance.completed` log for two hours, repeated `status: skipped`, or
  a non-decreasing `auditBacklogRemaining` across several runs;
- D1 capacity/latency, R2 write failures, or legacy-migration KV errors;
- Resend 4xx/5xx responses, email Queue retries/DLQ depth, and password-reset
  delivery failures;
- unusual login failures, refresh-token reuse, rate limits, or administrator changes.

Route Worker logs and audit events to a separate security log destination so an
identity-service outage does not remove its own evidence.

Configure Cloudflare WAF and edge rate-limiting rules as the first traffic
control layer for `/oauth/*`, public login and account-capability callbacks,
WebAuthn login verification, and `/health/ready`. The Worker's Durable Object
limits provide defense in depth and consistent application accounting; they do
not replace edge filtering during a volumetric attack. Likewise, the readiness
bearer credential restricts probe details but is not a substitute for an edge
allowlist where the monitoring service has stable egress addresses.

Enable GitHub's native secret scanning and push protection in repository
settings as a second layer. Dependabot configuration in `.github/dependabot.yml`
keeps application and GitHub Actions dependencies on a weekly update cadence.

## Backup and recovery

- Enable and periodically test D1 Time Travel. Keep encrypted pre-migration D1
  exports according to the organization's backup policy.
- Treat D1 `signing_key_state` as highly sensitive: it is the sole runtime
  authority and contains active/pending private signing material. KV is read
  only once when upgrading an installation that predates D1 key state. Cleanup
  is recorded durably, retried on later keyring loads, and keeps readiness red
  until both legacy KV keys are confirmed absent; the Worker never mirrors
  private keys back. Protect D1 exports accordingly; loss of KV after migration
  must not invalidate tokens.
- R2 is the long-term audit source after D1 retention. Restrict write/delete
  access to this Worker and backup operators.
- Keep client secrets and provider credentials in an external secret manager;
  the database stores only hashes where applicable.

Run a restore drill at least quarterly: restore D1 to an isolated database,
bind it to a temporary Worker, verify migration state and record counts, then
exercise discovery and a login without exposing the drill environment publicly.

### Signing-key rotation runbook

1. On every release and after each scheduled rotation, fetch discovery and
   JWKS, verify the active signing `kid` is published, and confirm no private
   RSA fields (`d`, `p`, `q`, and related parameters) appear. Readiness performs
   the active-key publication check automatically.
2. Correlate a rotation with `maintenance.completed`. If rotation fails, leave
   D1 untouched, preserve Worker logs, and investigate D1 capacity/availability
   first. Do not hand-edit `keyring_json` or restore legacy KV state over D1.
3. If D1 is lost or corrupted, contain writes and restore D1 with Time Travel.
   Validate `signing_key_state`, discovery, JWKS, and a newly signed token before
   reopening traffic. Do not recreate a KV private-key mirror.
4. For suspected private-key compromise, treat every JWT signed by that key as
   exposed. Revoke browser/refresh sessions, stage and publish a replacement,
   account for verifier JWKS caches, and use an emergency reviewed release to
   retire the compromised public key sooner than the normal grace window. Do
   not rely on ordinary scheduled rotation as incident containment.

### Audit Queue, DLQ, and R2 runbook

Audit writes carry stable IDs, so a Queue retry or controlled replay is
idempotent in D1. Administrative records keep the authenticated actor user or
client separately from the affected subject, and both actor fields are retained
in R2 archives after D1 aging. When DLQ depth is non-zero:

1. Stop the fault from generating more poison messages, preserve a sample and
   Worker exception logs, and determine whether the failure is schema, D1
   capacity, or a transient dependency issue. Never paste message payloads into
   tickets because audit metadata may be sensitive.
2. After correcting the consumer, attach a temporary, reviewed replay consumer
   to the DLQ that republishes validated messages to the normal audit Queue.
   Rate-limit replay below D1 capacity and retain the original event ID. Do not
   purge or delete the DLQ until D1 counts and event IDs are reconciled.
3. Quarantine malformed messages for security review instead of weakening
   validation. Record the replay window, counts, operator, and release version.

R2 archive keys are deterministic and uploads complete before source D1 rows
are deleted. Actor-aware payloads use `audit/v2/...` keys and
`schema_version: 2`; retention pruning continues scanning historical v1 and v2
prefixes. For an upload failure, leave the D1 rows in place and allow the next
hourly run to overwrite/retry the same key. If an archived object is
missing after its source rows have aged out of D1, restore it from the protected
R2/organization backup and reconcile its row IDs and date partition before
resuming pruning. Never manufacture an archive object or advance the persisted
R2 prune cursor to hide a gap.

### Transactional email Queue and DLQ runbook

Remote email is accepted into a dedicated Queue before the request reports a
successful send. Each job carries a stable random id that is reused as Resend's
idempotency key on every retry; the Queue retries provider timeouts and 5xx
failures five times before moving the job to the email DLQ. Message bodies can
contain short-lived login or recovery capabilities and must be handled as
sensitive authentication data.

When the email DLQ is non-empty:

1. Contain the provider/configuration failure, restrict DLQ access to identity
   operators, and inspect metadata without copying full message bodies into
   logs or tickets.
2. Correct the sender or Resend configuration, then attach a temporary reviewed
   replay consumer that republishes validated jobs with the original job id.
   Never mint a new idempotency key for a replay.
3. Let expired magic-link/recovery jobs fail safely; ask the user to request a
   new capability rather than extending or editing the queued URL. Reconcile
   replayed, expired, and quarantined counts before purging the DLQ.

## Rollback

Worker code and D1 schema have different rollback paths.

For a code-only regression with no schema dependency, find the previous healthy
version and roll back the Worker while leaving forward-compatible migrations in
place:

```bash
pnpm exec wrangler versions list --env production
pnpm exec wrangler rollback <healthy-version-id> --env production \
  --message 'rollback: production regression'
```

Before using Worker rollback, verify the old version understands every applied
column, constraint, and state representation. A non-forward-compatible D1
migration makes a code-only rollback unsafe: prefer a roll-forward fix. Never
attempt to reverse a D1 migration with ad-hoc `DROP`/`ALTER` statements in
production. If a migration corrupts data or is incompatible with the previous
Worker, stop writes if possible and restore D1 and Worker code as one coordinated
operation after recording the current bookmark/state:

```bash
pnpm exec wrangler d1 time-travel info keyforge --env production
pnpm exec wrangler d1 time-travel restore keyforge --env production
```

Restore commands are intentionally interactive; have two operators confirm the
target timestamp/bookmark. D1 Time Travel restores only D1. It does not rewind
Durable Objects, KV, R2, Queues, or secrets, so restoring an authorization
database without reconciliation can reactivate old sessions, users, password
hashes, client-secret hashes, grants, and signing-key state while refresh-token
families and one-time capabilities remain at a newer DO state.

Treat reconciliation as a release gate, not a post-restore observation:

1. Keep public traffic and all writes stopped. Save an encrypted export and the
   current Time Travel bookmark before restoring anything.
2. Restore D1 and the compatible Worker into an isolated, non-public target.
   Compare it with the pre-restore export and identify every security mutation
   after the target bookmark: user disable/delete, password or email change,
   client-secret rotation/disable, session or grant revocation, and signing-key
   transition.
3. Replay those mutations before exposure. Preserve the newest valid password
   and client-secret hashes from the encrypted snapshot; if a change cannot be
   reconstructed confidently, keep the affected user/client disabled and force
   a password reset or secret rotation.
4. Revoke all restored browser sessions and D1 refresh-token mirrors unless
   their post-bookmark state has been proven. Reconcile each surviving refresh
   family with its Durable Object; a D1-only update is not evidence that DO
   state was rewound. Let restored one-time capabilities expire rather than
   attempting to recreate their DO state.
5. Reconcile `signing_key_state` with the intended current keyring, publish its
   active and pending public keys, wait through the JWKS propagation window,
   and verify tokens from both sides of the restore boundary.
6. Only then deploy to the production route and restore traffic. Verify
   readiness, JWKS, fresh and pre-incident login behavior, token exchange and
   revocation, email delivery, Queue/DLQ consumption, and scheduled maintenance.

Record the bookmark, affected identities/clients, invalidation decision, and
two-operator approval in the incident log. A green liveness/readiness probe by
itself is not sufficient evidence that restored authentication state is safe.
