# Deployment guide moved

The maintained deployment and operations guide is
[docs/operations.md](docs/operations.md). It includes environment isolation,
one-time administrator bootstrap, release gates, D1-only 90/365-day audit
retention, legacy R2 removal, alerting, backup, and rollback procedures.

Quick verification commands:

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm test:coverage
pnpm audit --audit-level moderate
pnpm secrets:scan
pnpm deploy:dry-run:dev
pnpm deploy:dry-run:production
```
