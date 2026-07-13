# Deployment guide moved

The maintained deployment and operations guide is
[docs/operations.md](docs/operations.md). It includes environment isolation,
one-time administrator bootstrap, release gates, retention, alerting, backup,
and rollback procedures.

Quick verification commands:

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm test:coverage
pnpm exec wrangler deploy --dry-run --env staging
pnpm exec wrangler deploy --dry-run --env production
```
