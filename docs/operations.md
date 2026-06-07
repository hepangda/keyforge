# Operations

Operational runbooks for keyforge. Each entry is self-contained.

## Rotate JWKS signing key

keyforge runs a background rotation worker that introduces a fresh key
every 90 days (active) and retains old keys for 30 days (verifiable).
To force a manual rotation:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_AT" \
  https://auth.example.com:9090/admin/api/v1/jwks/rotate
```

The new `kid` appears in `/.well-known/jwks.json` immediately; the old
key keeps validating tokens it had previously signed until its
retention window expires.

## Rotate master key (KEK)

The KEK wraps per-row data encryption keys for JWKS private material,
TOTP secrets, and upstream IdP client secrets. Rotation re-wraps
every sealed row.

1. Set the new KEK as `KEYFORGE_JWKS__MASTER_KEY_NEXT`.
2. Restart keyforge; it re-wraps wrapped DEKs as they're read.
3. Once `keyforge_kek_rewrap_outstanding == 0`, promote `_NEXT` → main
   and remove the old value.

## Restore Postgres from backup

```bash
kubectl scale deploy/keyforge --replicas=0
pg_restore -d $DATABASE_URL <(...your snapshot...)
kubectl scale deploy/keyforge --replicas=$DESIRED
```

The keyforge binary applies any pending migrations on startup; no manual
`migrate` step is needed.

## Read the audit log

```bash
curl -H "Authorization: Bearer $ADMIN_AT" \
  "https://auth.example.com/admin/api/v1/audit?action=role.grant&limit=50"
```

Filter by `action`, `actor`, and `before` (RFC 3339 timestamp). The
table is INSERT-only at the database level so a compromised app role
cannot silently rewrite history.

## Respond to a brute-force alert

The lockout subsystem fires `keyforge_login_attempts_total{result="locked"}`
when an account is auto-locked. To inspect or manually unlock:

```bash
# Inspect failures for a specific tenant + email hash
psql -c "SELECT * FROM login_failures
         WHERE tenant_id = '<tid>' AND email_hash = decode('<hex>', 'hex')
         ORDER BY occurred_at DESC LIMIT 20;"

# Admin unlock through the API
curl -X DELETE -H "Authorization: Bearer $ADMIN_AT" \
  https://auth.example.com/admin/api/v1/lockouts/<tenant>/<email_hash>
```

## Expand tenant capacity

A new tenant is a single row in `tenants`, plus role assignments for
its admin user. The seed helper takes care of both:

```bash
docker compose run --rm seed --tenant acme --admin admin@acme.example
```

## Drain a node / rolling restart

```bash
kubectl rollout restart deploy/keyforge -n keyforge
kubectl rollout status  deploy/keyforge -n keyforge
```

PodDisruptionBudget (minAvailable=1) keeps at least one replica serving
during the rollout.
