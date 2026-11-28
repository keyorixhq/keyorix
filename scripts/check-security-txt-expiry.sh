#!/usr/bin/env bash
# Fails when the Expires field of docs/security/security.txt is in the past or
# less than MIN_DAYS (default 30) away, so a missed renewal is caught while
# there is still time to republish. Run it on a schedule (the nightly job), not
# on every PR: it reads the clock, which docs/guard-rollout-contract.md rule 1
# forbids for PR-time checks. The format and the one-year ceiling are checked
# by deploy/security_txt_test.go.
#
# Usage: scripts/check-security-txt-expiry.sh [path/to/security.txt]
#   MIN_DAYS=30   renewal lead time in days
#   NOW_EPOCH     override "now" (Unix seconds), for tests only
set -euo pipefail

file="${1:-docs/security/security.txt}"
min_days="${MIN_DAYS:-30}"

line="$(grep -E '^Expires:' "$file" || true)"
if [ -z "$line" ]; then
  echo "security.txt check: no Expires field in $file" >&2
  exit 1
fi
expires="$(printf '%s' "$line" | sed -E 's/^Expires:[[:space:]]*//; s/[[:space:]]+$//')"

# Expires is ISO 8601 in UTC: YYYY-MM-DDTHH:MM:SS[.fff]Z. Parse it with python3
# so the same script runs on macOS and Linux.
exp_epoch="$(python3 -I - "$expires" <<'PY'
import sys
from datetime import datetime, timezone
s = sys.argv[1]
if not s.endswith("Z"):
    sys.exit("Expires must be UTC (end in Z): " + s)
try:
    d = datetime.fromisoformat(s[:-1] + "+00:00")
except ValueError as e:
    sys.exit("Expires is not ISO 8601: %s (%s)" % (s, e))
print(int(d.timestamp()))
PY
)"

now_epoch="${NOW_EPOCH:-$(date -u +%s)}"
days=$(( (exp_epoch - now_epoch) / 86400 ))

if [ "$exp_epoch" -le "$now_epoch" ]; then
  echo "security.txt check: FAIL: Expires $expires has passed; renew it (docs/security/security-txt.md)" >&2
  exit 1
fi
if [ "$days" -lt "$min_days" ]; then
  echo "security.txt check: FAIL: Expires $expires is $days day(s) away, less than $min_days; renew it (docs/security/security-txt.md)" >&2
  exit 1
fi
echo "security.txt check: ok: Expires $expires is $days day(s) away (minimum $min_days)"
