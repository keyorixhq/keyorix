#!/usr/bin/env bash
# scripts/ci/check-govulncheck-test.sh -- offline calibration for
# check-govulncheck.sh: proves it goes red on a reachable, non-allowlisted
# finding AND green on a clean run, a non-reachable-only run, and a reachable
# run whose only finding is allowlisted -- the two directions
# CLAUDE.md's engineering practices ask every guard to prove before it's
# trusted. Runs entirely offline against canned govulncheck JSON (shaped
# exactly like real `govulncheck -format json ./...` output, captured
# 2026-11-06 against this repo's own main while GO-2026-6909 and GO-2026-6865
# were both live) -- it never calls the network or the real govulncheck
# binary except in the one case below that specifically tests what happens
# when the binary itself fails.
#
# Usage: scripts/ci/check-govulncheck-test.sh   (from anywhere)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$here/check-govulncheck.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); }
bad() {
	fail=$((fail + 1))
	echo "FAIL: $*" >&2
}

# expect STATUS DESC CMD...: runs CMD, compares exit status.
expect() {
	local want=$1 desc=$2 got=0 out
	shift 2
	out=$("$@" 2>&1) || got=$?
	if [ "$got" -eq "$want" ]; then
		ok
	else
		bad "$desc: want exit $want, got $got" "---" "$out"
	fi
	printf '%s' "$out"
}

# A finding with trace length 1 is module/package-level only -- present,
# never called. Real shape: GO-2026-5932 (x/crypto) on this repo's main.
cat >"$work/non_reachable_only.json" <<'EOF'
{
  "config": {
    "scanner_name": "govulncheck",
    "scanner_version": "v1.8.0"
  }
}
{
  "finding": {
    "osv": "GO-2026-5932",
    "fixed_version": "v0.58.1",
    "trace": [
      {
        "module": "golang.org/x/crypto",
        "version": "v0.58.0"
      }
    ]
  }
}
EOF

# A reachable finding (trace length 3) for GO-2026-6909, the ID this repo
# actually has a row for (docs/govulncheck-exceptions.d/GO-2026-6909.tsv) --
# plus the length-1 summary finding govulncheck also emits for the same ID,
# exactly like the real output captured against main.
cat >"$work/reachable_allowed.json" <<'EOF'
{
  "finding": {
    "osv": "GO-2026-6909",
    "trace": [
      { "module": "github.com/crewjam/saml", "version": "v0.5.1" }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2026-6909",
    "trace": [
      {
        "module": "github.com/crewjam/saml",
        "version": "v0.5.1",
        "package": "github.com/crewjam/saml",
        "function": "ParseResponse",
        "receiver": "*ServiceProvider"
      },
      {
        "module": "github.com/keyorixhq/keyorix",
        "package": "github.com/keyorixhq/keyorix/internal/saml",
        "function": "parseResponseRecovered",
        "receiver": "*Provider"
      },
      {
        "module": "github.com/keyorixhq/keyorix",
        "package": "github.com/keyorixhq/keyorix/internal/saml",
        "function": "ParseResponse",
        "receiver": "*Provider"
      }
    ]
  }
}
EOF

# A reachable finding for an ID with deliberately no row anywhere in this
# repo. If this ever starts passing, the allowlist match stopped being
# exact (e.g. turned into a prefix or substring match).
cat >"$work/reachable_blocking.json" <<'EOF'
{
  "finding": {
    "osv": "GO-2099-9999",
    "fixed_version": "N/A",
    "trace": [
      { "module": "example.com/nonexistent", "version": "v0.0.1" },
      { "module": "github.com/keyorixhq/keyorix", "package": "github.com/keyorixhq/keyorix/internal/fake", "function": "CallsIt" }
    ]
  }
}
EOF

# Both in one scan: the allowed one must not mask the blocking one.
cat "$work/reachable_allowed.json" "$work/reachable_blocking.json" >"$work/mixed.json"

echo "=== clean run, no findings at all ==="
echo '{"config":{"scanner_name":"govulncheck"}}' >"$work/clean.json"
out=$(expect 0 "clean run" bash "$script" --json-file "$work/clean.json")
echo "$out" | grep -q "clean (0 reachable" && ok || bad "clean run: expected a 0-reachable summary, got: $out"

echo "=== non-reachable-only finding passes with no row needed ==="
out=$(expect 0 "non-reachable-only" bash "$script" --json-file "$work/non_reachable_only.json")
echo "$out" | grep -q "GO-2026-5932" && bad "non-reachable-only: GO-2026-5932 should never be mentioned (it's not reachable, no row needed, no ID should even be considered)" || ok

echo "=== reachable + allowlisted (real row GO-2026-6909) passes and says so ==="
out=$(expect 0 "reachable allowed" bash "$script" --json-file "$work/reachable_allowed.json")
echo "$out" | grep -q "ALLOWED GO-2026-6909" && ok || bad "reachable allowed: expected an ALLOWED GO-2026-6909 line, got: $out"

echo "=== reachable + NOT allowlisted fails and names the ID ==="
out=$(expect 1 "reachable blocking" bash "$script" --json-file "$work/reachable_blocking.json")
echo "$out" | grep -q "BLOCKING GO-2099-9999" && ok || bad "reachable blocking: expected a BLOCKING GO-2099-9999 line, got: $out"

echo "=== one allowed + one blocking: the allowed one does not hide the blocking one ==="
out=$(expect 1 "mixed" bash "$script" --json-file "$work/mixed.json")
if echo "$out" | grep -q "ALLOWED GO-2026-6909" && echo "$out" | grep -q "BLOCKING GO-2099-9999"; then
	ok
else
	bad "mixed: expected both an ALLOWED GO-2026-6909 line and a BLOCKING GO-2099-9999 line, got: $out"
fi

echo "=== a near-miss ID (prefix of an allowlisted one) still blocks -- exact match only ==="
cat >"$work/near_miss.json" <<'EOF'
{
  "finding": {
    "osv": "GO-2026-69099",
    "trace": [
      { "module": "example.com/other", "version": "v0.0.1" },
      { "module": "github.com/keyorixhq/keyorix", "function": "CallsIt" }
    ]
  }
}
EOF
out=$(expect 1 "near-miss ID" bash "$script" --json-file "$work/near_miss.json")
echo "$out" | grep -q "BLOCKING GO-2026-69099" && ok || bad "near-miss ID: expected it to block, got: $out"

echo "=== govulncheck itself failing (nonzero exit) fails the check, not silently 'clean' ==="
fake_bin_dir="$work/fakebin"
mkdir -p "$fake_bin_dir"
cat >"$fake_bin_dir/govulncheck" <<'EOF'
#!/usr/bin/env bash
echo "simulated build failure" >&2
exit 1
EOF
chmod +x "$fake_bin_dir/govulncheck"
out=$(PATH="$fake_bin_dir:$PATH" expect 1 "govulncheck tool failure" bash "$script")
echo "$out" | grep -q "simulated build failure" && ok || bad "govulncheck tool failure: expected the real stderr to surface, got: $out"

echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
