#!/usr/bin/env bash
# scripts/ci/run-input-guards.sh CHANGED_LIST -- the guard tests whose inputs a
# change touched (ci.yml docs-guards job, CI-GUARD-TRIGGERS-1).
#
# Every Go job in ci.yml skips a docs_only / web_only / go_unaffected /
# operator_only change, so a guard that reads a Markdown file, web/nginx.conf, a
# script or operator/ code needs a runner that does not (#3616: a QUICK_START.md
# change merged past TestDocsShowNoLiteralSecretOnCommandLine and turned main
# red). scripts/ci/guard-inputs.tsv maps each such guard test file to its input
# globs; this runs the Test funcs of every file with a glob matching a path in
# CHANGED_LIST (one path per line). An empty list runs every mapped file.
# scripts/ci/guardinputs/guardinputs_test.go keeps the map complete against the
# test sources and against ci.yml's own path classification.
#
# Usage: scripts/ci/run-input-guards.sh changed.txt   (from the repository root)
set -euo pipefail

list=${1:?usage: run-input-guards.sh <file with one changed path per line>}
echo "docs-guards: $(grep -c . "$list" || true) changed path(s); selecting from scripts/ci/guard-inputs.tsv"
plan=$(go run ./scripts/ci/guardinputs select < "$list")
if [ -z "$plan" ]; then
  echo "docs-guards: no mapped guard reads a changed path; nothing to run"
  exit 0
fi
echo "docs-guards: plan (module, package, tests):"
printf '%s\n' "$plan"

status=0
while IFS=$'\t' read -r mod pkg rx; do
  gw=${GOWORK:-}
  [ "$mod" != "." ] && gw=off
  echo "docs-guards: [$mod] go test -run '$rx' $pkg"
  if ! (cd "$mod" && GOWORK=$gw go test -count=1 -timeout 1200s -run "$rx" "$pkg"); then
    status=1
  fi
done <<<"$plan"
if [ "$status" -ne 0 ]; then
  echo "docs-guards: FAILED -- a guard whose input this change touched is red; see the --- FAIL lines above" >&2
else
  echo "docs-guards: every selected guard passed"
fi
exit "$status"
