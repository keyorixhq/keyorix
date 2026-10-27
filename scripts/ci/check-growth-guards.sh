#!/usr/bin/env bash
# Architecture-growth guard: fails when a package of the root module under
# internal/ or server/ outgrows a ceiling.
#
#   (a) files-per-package: non-test .go files in one package
#   (b) dependents-per-package: packages of the module that transitively import it
#
# Why: every package that keeps growing makes each later change touch more
# files, collide with more PRs, rebuild more of the tree and cost more CI and
# review. Nobody pays that bill at design time, so the build does. Baseline,
# method and the reasons for the numbers: docs/design/architecture-growth-baseline.md.
#
# Calibration (2026-10-27, measured by this same script on origin/main bf93a951c):
#   files:      today's max is 226 (internal/core), ceiling 260 = 1.15x
#   dependents: today's max is 38 (internal/core/ports), ceiling 44 = 1.16x
# Files, not LOC, because LOC counts generated code (server/proto/pb is 2 files and
# 17k lines, internal/faultstorage 3 files and 8k lines) while a file count does
# not move when a generator runs; the file count does rise when people add yet
# another file to a package that is already the dumping ground.
#
# When growth is intended: raise the ceiling here, in the PR that causes it, and
# record the new baseline row and the reason in the design doc. Do not raise it
# silently. Better: split the package.
#
#   scripts/ci/check-growth-guards.sh              # check against the ceilings
#   scripts/ci/check-growth-guards.sh --print      # the measurement, worst first
#   scripts/ci/check-growth-guards.sh --self-test  # red/green proof the check fires
#
# Env overrides (for experiments, not for CI): GROWTH_MAX_FILES, GROWTH_MAX_DEPENDENTS.
# cli/ and operator/ are separate Go modules and are not measured.
set -euo pipefail

MAX_FILES="${GROWTH_MAX_FILES:-260}"
MAX_DEPENDENTS="${GROWTH_MAX_DEPENDENTS:-44}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
measure="$here/growth_measure.py"

run_check() { # max_files max_dependents
  python3 -I "$measure" --root "$root" --check --max-files "$1" --max-dependents "$2"
}

case "${1:-}" in
  --print)
    python3 -I "$measure" --root "$root" --table files --top 25
    exit 0
    ;;
  --self-test)
    echo "growth-guards self-test: measuring (go list ./... takes a few seconds)" >&2
    rows="$(python3 -I "$measure" --root "$root" --json)"
    worst_f="$(python3 -I -c 'import json,sys; print(max(r["files"] for r in json.load(sys.stdin)))' <<<"$rows")"
    worst_d="$(python3 -I -c 'import json,sys; print(max(r["dependents"] for r in json.load(sys.stdin)))' <<<"$rows")"
    # red: ceilings one below the real worst offenders must fail and name both
    if out="$(run_check $((worst_f - 1)) $((worst_d - 1)))"; then
      echo "SELF-TEST FAIL: ceilings below the real maximum did not fail" >&2; exit 1
    fi
    grep -q "non-test .go files, ceiling $((worst_f - 1)) (over by 1" <<<"$out" ||
      { echo "SELF-TEST FAIL: files failure message missing: $out" >&2; exit 1; }
    grep -q "transitive dependents, ceiling $((worst_d - 1)) (over by 1" <<<"$out" ||
      { echo "SELF-TEST FAIL: dependents failure message missing: $out" >&2; exit 1; }
    # green: ceilings equal to the real maximum must pass
    run_check "$worst_f" "$worst_d" >/dev/null ||
      { echo "SELF-TEST FAIL: ceilings equal to the real maximum failed" >&2; exit 1; }
    echo "growth-guards self-test OK: red at max-1 (files $worst_f, dependents $worst_d), green at max"
    exit 0
    ;;
  "") ;;
  *) echo "usage: $0 [--print|--self-test]" >&2; exit 2 ;;
esac

echo "growth-guards: ceilings files<=$MAX_FILES dependents<=$MAX_DEPENDENTS (measuring, a few seconds)" >&2
if out="$(run_check "$MAX_FILES" "$MAX_DEPENDENTS")"; then
  echo "$out"
  echo "growth-guards OK"
  exit 0
fi
echo "$out"
cat >&2 <<EOF

growth-guards FAILED: a package outgrew its ceiling (lines above say which and by how much).
What to do next:
  1. Split the package: move the new code into a new sub-package, or a leaf package
     with a narrow interface, instead of adding to the one that is already big/central.
  2. If the growth is intended, raise the ceiling in scripts/ci/check-growth-guards.sh in
     this PR and add the reason to docs/design/architecture-growth-baseline.md.
  3. Rule and numbers: docs/ARCHITECTURE.md, "Growth ceilings".
EOF
exit 1
