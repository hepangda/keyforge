# Operations runbook

This runbook covers provisioning, releases, scheduled maintenance, backup,
rollback, and alerting. Commands assume Wrangler 4 from this repository.

## Operator prerequisites

Use Node.js 20-26 and pnpm 10, then authenticate Wrangler to the intended
Cloudflare account before provisioning or releasing:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm exec wrangler whoami
# If whoami is not authenticated:
pnpm exec wrangler login
```

Have the `auth-staging.pangda.app` and `auth.pangda.app` DNS zones in the same
account, a verified Resend sender, a monitoring secret manager, and two
operators for destructive production restore or legacy-bucket deletion.

## Environment model

`wrangler.toml` defines three isolated binding sets:

| Configuration | Remote target | Issuer |
| --- | --- | --- |
| top-level | local development and tests only | `http://localhost:8787` |
| `staging` | `keyforge-staging` | `https://auth-staging.pangda.app` |
| `production` | `keyforge` | `https://auth.pangda.app` |

D1, KV, and both Queue/DLQ pairs are separate in staging and production.
KeyForge has no R2 binding and creates no audit archive outside D1.
Any all-zero D1/KV IDs are deliberate placeholders; the current production
profile still has both. Resource identifiers are not secrets and should replace
the matching placeholders in `wrangler.toml` after provisioning so every
operator and CI validates and deploys the same bindings.

Remote migration and deploy package scripts run a fail-closed preflight. It
rejects placeholder or shared D1/KV IDs, missing bindings, mismatched Queue
producer/consumer names, missing required-secret declarations, non-hourly
maintenance, any R2 binding or archive retention variable, an audit retention
other than 90 days in staging or 365 days in production, and any disagreement
between the selected environment, issuer, Worker, and custom-domain route. A
Wrangler dry run remains available separately because it validates the build
and TOML shape without proving that provisioned resources exist.

Create one complete resource set per environment:

```bash
pnpm exec wrangler d1 create keyforge_staging
pnpm exec wrangler kv namespace create KV --env staging
pnpm exec wrangler queues create keyforge-audit-staging
pnpm exec wrangler queues create keyforge-audit-staging-dlq
pnpm exec wrangler queues create keyforge-email-staging
pnpm exec wrangler queues create keyforge-email-staging-dlq

pnpm exec wrangler d1 create keyforge
pnpm exec wrangler kv namespace create KV --env production
pnpm exec wrangler queues create keyforge-audit
pnpm exec wrangler queues create keyforge-audit-dlq
pnpm exec wrangler queues create keyforge-email
pnpm exec wrangler queues create keyforge-email-dlq
```

Copy the returned D1 and KV identifiers into only the matching environment in
`wrangler.toml`. Queue names are already explicit. Do not create an R2 bucket
or an R2 API credential for KeyForge.

```bash
pnpm validate:deploy:staging
pnpm validate:deploy:production
```

Both commands must pass before any remote migration or deployment.

## Secrets and first administrator

Set secrets independently in each environment. Remote readiness requires a
random `REQUEST_HASH_SECRET` and a dedicated `READINESS_PROBE_TOKEN`, each at
least 32 characters. Generate a different readiness token for staging and
production, store the matching copy in the monitoring system's secret manager,
and do not reuse an OAuth client secret. Because remote email uses Resend, it
also requires both `RESEND_API_KEY` and `EMAIL_FROM`. Social providers are
optional, but each configured provider requires both its client ID and client
secret.

The `[env.*.secrets]` sections declare the four core secret names as required,
so a normal deploy fails if any is absent. For the first deployment, create a
mode-`0600` JSON or dotenv bundle outside the repository and pass it through
Wrangler's `--secrets-file`; include `BOOTSTRAP_TOKEN` only while creating the
first administrator. A JSON bundle has this shape:

```json
{
  "RESEND_API_KEY": "replace-with-secret-manager-value",
  "EMAIL_FROM": "replace-with-verified-sender",
  "REQUEST_HASH_SECRET": "replace-with-new-random-64-hex",
  "READINESS_PROBE_TOKEN": "replace-with-different-random-64-hex",
  "BOOTSTRAP_TOKEN": "replace-with-one-time-random-64-hex"
}
```

Before the first deploy, replace `ENVIRONMENT` with `staging` or `production`,
point the variable at that absolute path, and verify permissions:

```bash
export KEYFORGE_SECRETS_FILE=/secure/tmp/keyforge-ENVIRONMENT.secrets.json
chmod 600 "$KEYFORGE_SECRETS_FILE"
```

The individual commands below are for an already deployed Worker whose D1
migrations are current. `wrangler secret put` creates and immediately deploys
a new Worker version; never use it as a harmless pre-deploy staging command.

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

Configure production separately and generate a different readiness token:

```bash
pnpm exec wrangler secret put RESEND_API_KEY --env production
pnpm exec wrangler secret put EMAIL_FROM --env production
pnpm exec wrangler secret put REQUEST_HASH_SECRET --env production
READINESS_PROBE_TOKEN="$(openssl rand -hex 32)"
printf '%s' "$READINESS_PROBE_TOKEN" | pnpm exec wrangler secret put READINESS_PROBE_TOKEN --env production
# Store this value in the production monitor's secret manager, then unset it.
unset READINESS_PROBE_TOKEN
pnpm exec wrangler secret put GITHUB_CLIENT_ID --env production
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET --env production
pnpm exec wrangler secret put GOOGLE_CLIENT_ID --env production
pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET --env production
```

Omit both commands for any provider that is disabled; never configure only one
member of an ID/secret pair. Keep `ALLOW_SELF_SIGNUP="false"` unless the tenant
has an explicit open-registration policy; the value must be the literal `true`
or `false`. Secret values never belong in `wrangler.toml`, `.dev.vars.example`,
logs, support tickets, or D1 exports shared with developers.

Removing R2 does not remove or add an application secret: there was no R2
access key in the Worker. Required remote secrets remain `RESEND_API_KEY`,
`EMAIL_FROM`, `REQUEST_HASH_SECRET`, and `READINESS_PROBE_TOKEN`; GitHub and
Google credentials remain optional complete pairs. `BOOTSTRAP_TOKEN` is
temporary and must be deleted after the first administrator is verified.

Migrations contain no password or administrator. Bootstrap staging and
production separately, with a new random token for each environment. Include
the token in the first-deploy secrets bundle, or set it only after migrations
and the initial Worker deployment have completed. Then call the endpoint.

For staging:

```bash
# If BOOTSTRAP_TOKEN was in the first-deploy bundle, load that same value from
# the secret manager and skip the following two lines.
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
# If BOOTSTRAP_TOKEN was in the first-deploy bundle, load that same value from
# the secret manager and skip the following two lines.
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

   `pnpm audit --audit-level moderate` queries the package registry and blocks
   the release for moderate, high, or critical dependency advisories. It does
   not inspect business audit logs or secrets, and a registry/network error is
   not a pass. `pnpm secrets:scan` is a complementary pattern scan of tracked
   and non-ignored repository files; it does not inspect ignored local secret
   files and does not replace GitHub push protection or an external secret
   manager.

2. Record the current D1 Time Travel bookmark and export schema only before a
   migration. The default release path deliberately avoids a full-data export,
   because that would create another copy of audit rows with no row-level
   expiry:

   ```bash
   install -d -m 700 backups
   pnpm exec wrangler d1 time-travel info keyforge_staging --env staging
   pnpm exec wrangler d1 export keyforge_staging --env staging --remote \
     --no-data --output backups/keyforge_staging-schema.sql
   ```

   Store the schema export encrypted outside the repository and delete the
   local copy. If incident response requires a full-data export, access must be
   restricted and every copy must be destroyed before any contained audit row
   exceeds the environment's 90/365-day limit.

3. Apply and validate staging:

   ```bash
   pnpm db:migrate:staging
   # Existing Worker with all four required secrets:
   pnpm deploy:staging
   # Load the staging readiness token from the monitoring secret manager.
   curl -fsS https://auth-staging.pangda.app/health/ready \
     -H "Authorization: Bearer $READINESS_PROBE_TOKEN"
   ```

   For a first deployment, replace `pnpm deploy:staging` with the following
   atomic code-and-secret upload; do not run both deploy commands:

   ```bash
   pnpm validate:deploy:staging
   pnpm exec wrangler deploy --env staging \
     --secrets-file "$KEYFORGE_SECRETS_FILE"
   rm -f "$KEYFORGE_SECRETS_FILE"
   unset KEYFORGE_SECRETS_FILE
   ```

4. Exercise discovery, JWKS, login, authorization code + PKCE, refresh, email,
   and an administrator mutation in staging.

5. Record the production bookmark, export schema only, apply migrations, then
   deploy. First inspect the current database size and peak recent daily audit
   volume; do not continue if the projected 365-day footprint exceeds the D1
   plan or `peak_daily_rows` exceeds the 28,800-row cleanup capacity:

   ```bash
   pnpm exec wrangler d1 info keyforge --env production
   pnpm exec wrangler d1 execute keyforge --env production --remote \
     --command "SELECT MAX(daily_rows) AS peak_daily_rows FROM (SELECT created_at / 86400 AS utc_day, COUNT(*) AS daily_rows FROM audit_logs WHERE created_at >= unixepoch() - 30 * 86400 GROUP BY utc_day)"
   pnpm exec wrangler d1 time-travel info keyforge --env production
   pnpm exec wrangler d1 export keyforge --env production --remote \
     --no-data --output backups/keyforge-schema.sql
   pnpm db:migrate:production
   # Existing Worker with all four required secrets:
   pnpm deploy:production
   # Load the production readiness token from the monitoring secret manager.
   curl -fsS https://auth.pangda.app/health/ready \
     -H "Authorization: Bearer $READINESS_PROBE_TOKEN"
   ```

   For the first production deployment, replace `pnpm deploy:production` with
   the atomic upload below; do not run both deploy commands:

   ```bash
   pnpm validate:deploy:production
   pnpm exec wrangler deploy --env production \
     --secrets-file "$KEYFORGE_SECRETS_FILE"
   rm -f "$KEYFORGE_SECRETS_FILE"
   unset KEYFORGE_SECRETS_FILE
   ```

Do not deploy if readiness is not `200` with every check marked `ok`.

`pnpm db:migrate:*` and `pnpm deploy:*` (except `deploy:dry-run:*`) refuse to
continue until real, isolated remote resource IDs are present. This is expected
on an unprovisioned checkout; never bypass it by copying production IDs into
staging or by invoking raw Wrangler commands as a release shortcut.

### One-time R2 removal rollout

Use this section only for an installation that previously used
`keyforge-archive-staging` or `keyforge-archive`. Removing a binding does not
delete existing objects. The default compliance migration does not copy archive
objects back into D1; this means historical coverage grows from the old D1
windows to the new 90/365-day windows over time. Do not create a temporary
backfill unless the business explicitly requires it and the import filters out
every row already beyond the new limit.

1. Deploy and verify staging with the release procedure above. Confirm the
   readiness response contains no `audit_archive` check and, after the next
   minute-15 cron, confirm a successful `maintenance.completed` log.
2. Verify no expired online audit row remains:

   ```bash
   pnpm exec wrangler d1 execute keyforge_staging --env staging --remote \
     --command "SELECT COUNT(*) AS expired_rows, MIN(created_at) AS oldest_expired_at FROM audit_logs WHERE created_at < unixepoch() - 90 * 86400"
   ```

   Require `expired_rows = 0`. A non-zero value means the cleanup backlog must
   drain before the rollout continues.
3. In Cloudflare Dashboard, open **R2 object storage** >
   `keyforge-archive-staging` > **Settings** > **Empty Bucket** > **Empty**.
   Remove any bucket lock first. After the background operation completes,
   permanently delete the empty bucket and verify its name is absent from:

   ```bash
   pnpm exec wrangler r2 bucket list
   ```

4. Repeat steps 1-3 in production, using `365 * 86400` and the bucket
   `keyforge-archive`. The empty bucket can alternatively be deleted with:

   ```bash
   pnpm exec wrangler r2 bucket delete keyforge-archive-staging
   pnpm exec wrangler r2 bucket delete keyforge-archive
   ```

   If `pnpm exec wrangler r2 bucket list` also shows a remotely created legacy
   `keyforge-archive-local`, empty and delete it by the same procedure.
5. Destroy old R2/D1 exports, CI artifacts, restore-drill databases, support
   samples, and external log copies that exceed the same environment limit.
   Record deletion evidence: readiness green, expired D1 count zero, both R2
   names absent, and no `ARCHIVE` binding in the deployed Worker.

Emptying a bucket is irreversible. After either old bucket is emptied, no
Worker version that depends on `ARCHIVE` is a valid rollback target. Fix
regressions by rolling forward or by publishing a no-R2-compatible build.

## Scheduled maintenance and retention

The `15 * * * *` UTC cron runs hourly at minute 15, acquires a D1 lease, and
then performs bounded work so an accumulated audit backlog drains over
successive invocations:

- rotates the active RS256 signing key when it is seven days old;
- retains retired public keys through the token verification grace window;
- directly deletes audit rows from D1 when they are older than 90 days in
  staging or 365 days in production, without creating an archive copy;
- removes expired/revoked sessions, refresh tokens, device sessions, grant
  history, and one-time token rows after the configured terminal retention
  window (14 days in staging and 30 days in production).

The deployment validator and remote runtime both enforce the environment's
exact audit limit. Each delete statement selects the oldest indexed candidates
and deletes at most 100 rows; a run performs at most 12 audit batches. With an
hourly cron this is a maximum drain rate of 28,800 rows per day. Before release,
confirm the tenant's daily audit volume stays below this rate and that the
365-day production footprint fits the D1 plan.

Successful runs log `maintenance.completed`, including `deletedAuditRows`, the
remaining eligible audit backlog, and the oldest eligible row. A thrown error
leaves rows not yet deleted in D1 and lets the next hourly invocation retry; the
lease expires after 15 minutes if an isolate terminates unexpectedly. Do not
change the cron back to daily: the bounded D1 query budget relies on frequent
small batches. Because an hourly cron can delete almost one hour after the
logical boundary, confirm that this scheduling tolerance matches the governing
retention rule.

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
actor lookup indexes, the audit-retention index, and bounded-cleanup indexes;
the identity uniqueness index; the administrator seed catalog; the
D1-authoritative signing key, published JWKS, and completed legacy-KV cleanup;
both Queue metrics; and a Durable Object RPC. It returns no secret values or
failure details. Alert on:

- readiness failing twice within two minutes;
- Worker 5xx rate or `/oauth/token` latency/error rate exceeding the service SLO;
- audit or transactional-email Queue backlog age, DLQ messages, or repeated
  queue-consumer retries;
- no `maintenance.completed` log for two hours, repeated `status: skipped`, or
  a non-decreasing `auditBacklogRemaining` across several runs;
- D1 capacity/latency, audit-retention delete failures, or legacy-migration KV
  errors;
- Resend 4xx/5xx responses, email Queue retries/DLQ depth, and password-reset
  delivery failures;
- unusual login failures, refresh-token reuse, rate limits, or administrator changes.

Route operational Worker logs to a separate security destination so an
identity-service outage does not remove its own evidence. Do not forward full
audit payloads unless that destination enforces the same maximum: 90 days for
staging and 365 days for production. Queue/DLQ samples, tickets, and incident
attachments are subject to the same limit.

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

- D1 Time Travel is always on. Its recovery window is currently 30 days on a
  Workers Paid plan and 7 days on a Free plan. Therefore the scheduled SQL
  `DELETE` enforces the online/logical 90/365-day limit but does not guarantee
  immediate physical irrecoverability. If the governing rule counts provider
  recovery history, obtain a compliance determination before launch; the
  application may need an earlier logical cutoff or a storage service with a
  controllable backup window.
- Do not retain full D1 exports under a generic backup period. Schema-only
  release exports contain no audit rows. Any exceptional full-data export,
  restored database, SIEM copy, Queue/DLQ sample, or incident attachment must
  be access-controlled and destroyed before its oldest audit row crosses the
  environment's 90/365-day limit.
- Treat D1 `signing_key_state` as highly sensitive: it is the sole runtime
  authority and contains active/pending private signing material. KV is read
  only once when upgrading an installation that predates D1 key state. Cleanup
  is recorded durably, retried on later keyring loads, and keeps readiness red
  until both legacy KV keys are confirmed absent; the Worker never mirrors
  private keys back. Protect D1 exports accordingly; loss of KV after migration
  must not invalidate tokens.
- Keep client secrets and provider credentials in an external secret manager;
  the database stores only hashes where applicable.

Run a restore drill at least quarterly: restore D1 to an isolated database,
apply the audit-retention delete before exposing or querying restored audit
data, bind it to a temporary Worker, verify migration state and record counts,
then exercise discovery and a login without exposing the drill environment
publicly. Destroy the drill database within the applicable retention limit.

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

### Audit Queue, DLQ, and retention cleanup runbook

Audit writes carry stable IDs, so a Queue retry or controlled replay is
idempotent in D1. Administrative records keep the authenticated actor user or
client separately from the affected subject. No archive copy is created. When
DLQ depth is non-zero:

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

For retention cleanup failures, inspect the D1 exception and the next
`maintenance.completed` result. Compare `auditBacklogRemaining` and
`oldestEligibleAuditAt` across hourly runs; both must drain toward zero. Do not
export overdue payloads for troubleshooting or restore deleted rows from a
backup. If the daily ingest rate can exceed 28,800 rows or the backlog does not
decrease, stop the release and increase reviewed cleanup capacity before the
retention boundary is breached.

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

The first no-R2 release is a rollback floor. After either legacy archive bucket
is emptied, never roll back to a version that declares or reads `ARCHIVE`.
Publish a forward fix or rebuild the desired older business changes on top of
the no-R2 retention implementation.

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
Durable Objects, KV, Queues, or secrets, so restoring an authorization
database without reconciliation can reactivate old sessions, users, password
hashes, client-secret hashes, grants, and signing-key state while refresh-token
families and one-time capabilities remain at a newer DO state.

Treat reconciliation as a release gate, not a post-restore observation:

1. Keep public traffic and all writes stopped. Record the current Time Travel
   bookmark before restoring anything. If an exceptional encrypted full-data
   export is required, restrict it and assign a destruction deadline that
   cannot extend any contained audit row beyond 90/365 days.
2. Restore D1 and the compatible Worker into an isolated, non-public target.
   Compare it with the approved change record and any compliant incident
   snapshot, then identify every security mutation after the target bookmark:
   user disable/delete, password or email change,
   client-secret rotation/disable, session or grant revocation, and signing-key
   transition. A restore can also revive audit rows that have crossed the
   retention limit. Before any traffic resumes, repeat this bounded production
   cleanup until the following count is zero (use 90 days for staging):

   ```bash
   pnpm exec wrangler d1 execute keyforge --env production --remote \
     --command "DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < unixepoch() - 365 * 86400 ORDER BY created_at, id LIMIT 10000)"
   pnpm exec wrangler d1 execute keyforge --env production --remote \
     --command "SELECT COUNT(*) AS expired_rows FROM audit_logs WHERE created_at < unixepoch() - 365 * 86400"
   ```

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
