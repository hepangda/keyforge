#!/usr/bin/env bash
# conformance.sh — placeholder hook for the OIDF conformance suite.
#
# The real test runner is provided by the OpenID Foundation and runs in
# a separate container; this script writes a minimal report shaped like
# the suite's own output so the CI workflow's artifact upload step
# always succeeds.
#
# To enable the actual suite locally:
#   1. Pull openid-foundation/conformance-suite per their README.
#   2. Configure it against http://localhost:8080.
#   3. Replace the body below with their docker-run invocation.
set -euo pipefail

mkdir -p conformance
cat > conformance/report.json <<'EOF'
{
  "status": "skipped",
  "reason": "conformance harness placeholder — wire the OIDF suite in CI to populate this report"
}
EOF
echo "Conformance placeholder report written."
