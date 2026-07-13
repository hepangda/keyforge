-- Serialize scheduled maintenance. Cloudflare may deliver overlapping cron
-- invocations or retry a timed-out event; the owner token prevents one run
-- from releasing another run's lease.
CREATE TABLE maintenance_leases (
  job_name      TEXT PRIMARY KEY,
  owner_token   TEXT NOT NULL,
  lease_until   INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE INDEX idx_maintenance_leases_expiry ON maintenance_leases (lease_until);
