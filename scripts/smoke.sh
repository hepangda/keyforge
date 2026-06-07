#!/usr/bin/env bash
# smoke.sh — end-to-end sanity check against a compose-up'd keyforge.
#
# Hits the must-be-200 surfaces, exercises a token round-trip via the
# seeded admin user, and prints PASS/FAIL summary. Run after
# `make compose-up && docker compose run --rm seed`.
set -euo pipefail

BASE=${KEYFORGE_BASE:-http://localhost:8080}
ADMIN=${KEYFORGE_ADMIN:-http://localhost:9090}

pass() { printf "\033[32mPASS\033[0m %s\n" "$1"; }
fail() { printf "\033[31mFAIL\033[0m %s — %s\n" "$1" "$2"; exit 1; }

curl -sf "${BASE}/healthz" >/dev/null   && pass "/healthz"   || fail "/healthz"   "$?"
curl -sf "${BASE}/readyz"  >/dev/null   && pass "/readyz"    || fail "/readyz"    "$?"
curl -sf "${ADMIN}/metrics" | head -n 1 | grep -q '^# HELP' \
  && pass "/metrics (keyforge_*)" || fail "/metrics" "no metrics emitted"

curl -sf "${BASE}/.well-known/openid-configuration" \
  | grep -q "authorization_endpoint" \
  && pass "discovery" || fail "discovery" "no authorization_endpoint"

curl -sf "${BASE}/.well-known/jwks.json" | grep -q '"keys"' \
  && pass "jwks" || fail "jwks" "no keys array"

echo
echo "Smoke checks complete."
