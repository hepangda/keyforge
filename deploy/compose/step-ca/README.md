# keyforge step-ca

This directory holds the bootstrap material for the local development
[step-ca](https://smallstep.com/docs/step-ca) instance that issues TLS client
certificates we use to exercise the mTLS client-authentication and
certificate-bound-token flows (RFC 8705) against keyforge.

- `password` — the root password for the development CA. **Do not** reuse this
  outside of `docker-compose up`. The compose stack mounts it read-only at
  `/home/step/secrets/password`.

The CA data (root cert, intermediate, JSON-formatted state) lives in the
`step-ca-data` docker volume so that `compose down -v` wipes it cleanly.
