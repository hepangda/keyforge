#!/bin/sh
# init.sh — bootstrap a single-tenant step-ca instance on first run.
# Subsequent starts reuse the persisted state under /home/step.
set -eu

CA_DIR=/home/step

if [ ! -f "${CA_DIR}/certs/root_ca.crt" ]; then
  echo "Bootstrapping step-ca..."
  step ca init \
    --name "keyforge-dev" \
    --dns "step-ca" \
    --address ":9000" \
    --provisioner "admin" \
    --password-file=/dev/stdin \
    --acme \
    --no-db \
    --provisioner-password-file=/dev/stdin <<EOF
keyforge-dev
keyforge-dev
EOF
fi

exec step-ca --password-file=/dev/stdin "${CA_DIR}/config/ca.json" <<EOF
keyforge-dev
EOF
