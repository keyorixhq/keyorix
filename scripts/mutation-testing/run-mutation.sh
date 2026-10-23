#!/usr/bin/env bash
# Weekly mutation-testing run. Intended as a systemd oneshot service (see
# systemd/keyorix-mutation.service + .timer) on a dedicated box, separate
# from CI, for the same reason scripts/fuzzing/ lives there: gremlins
# re-runs the target package's test suite once per surviving mutant, which
# on a large package like internal/core is genuinely slow -- well beyond
# what a CI job's budget affords (see .semgrep/RULE-MINING-PROCESS.md and
# this repo's mutation-testing history for why this exists at all).
#
# For each target package (see PACKAGES below): pulls the repo fresh, runs
# `gremlins unleash`, saves the JSON result, computes a summary, and
# compares it against the LAST recorded summary for that package. Always
# sends a normal-priority ntfy.sh summary. If test efficacy regressed (or
# a new package's baseline is being recorded for the first time), also
# opens/updates a GitHub issue and sends a high-priority alert -- mirroring
# notify-on-crash.sh's dedup-by-marker-file pattern, but for "test quality
# got worse" instead of "fuzzer found a crash."
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${KEYORIX_REPO:?set KEYORIX_REPO to the path of the main keyorix git clone}"
: "${MUTATION_STATE_DIR:=$SCRIPT_DIR/.state}"
: "${MUTATION_WORKERS:=4}"
: "${MUTATION_EFFICACY_DROP_THRESHOLD:=5}" # percentage points

# Go's default GOMAXPROCS reads the host's visible thread count, not this
# service's CPUQuota (systemd/keyorix-mutation.service) or the container's
# actual core budget -- so each of MUTATION_WORKERS concurrent `go build`/
# `go test` subprocesses independently spins up threads for ALL visible
# threads, not its fair share. With workers=4 on an 8-thread host that's up
# to 32 runnable threads fighting over a 4-core CPUQuota, which doesn't
# break the quota but does starve individual `go test` runs long enough to
# blow gremlins' per-mutant timeout -- every mutant comes back TIMED OUT
# instead of KILLED/LIVED. Cap each worker to its fair share so total
# demand matches the real budget instead of oversubscribing it 8x.
export GOMAXPROCS="${MUTATION_GOMAXPROCS:-1}"

# summarize.py (invoked below as a child process) reads MUTATION_STATE_DIR
# itself to locate its input file -- a plain `:` default-assignment doesn't
# export to child processes, so make sure it's actually visible there even
# when this script is run standalone (outside systemd, which already
# exports it via config.env's EnvironmentFile).
export MUTATION_STATE_DIR

mkdir -p "$MUTATION_STATE_DIR"

# Packages to mutation-test, one per line:
# "<go-package-path>|<label>[|<min-efficacy-pct>]". Widen this deliberately,
# one package at a time, as each is brought into good shape -- see .github's
# retired mutation-testing.yml (superseded by this script) for the reasoning
# on why this starts scoped to two packages instead of the whole repo.
#
# The optional third field is an absolute floor, measured when the package was
# brought in (MUTANT-SEC-1, gremlins --workers 1). Falling below it fails the
# run at the end, in addition to the relative-regression notice from
# notify-summary.sh. The remaining survivors in these packages are equivalent
# mutants (see the item commits), so the floor is the measured value, not 100.
PACKAGES="internal/core|core
internal/storage/store|storage-store
internal/keyfiles|keyfiles|93.55
internal/securefiles|securefiles|98.31
internal/recoverykey|recoverykey|82.35
internal/evidencesink|evidencesink|100"

cd "$KEYORIX_REPO"

echo "=== $(date -u +%FT%TZ) pulling latest main ==="
git fetch origin main --quiet
git checkout main --quiet
git reset --hard origin/main --quiet

below_floor=0

while IFS='|' read -r pkg label min_efficacy; do
  [[ -z "$pkg" ]] && continue
  case "$pkg" in \#*) continue ;; *) ;; esac

  echo "=== $(date -u +%FT%TZ) mutation-testing ./$pkg ($label) ==="
  result_json="$MUTATION_STATE_DIR/last-$label.json"
  result_json_tmp="$result_json.tmp"
  summary_json="$MUTATION_STATE_DIR/last-$label-summary.json"
  summary_json_prev="$MUTATION_STATE_DIR/prev-$label-summary.json"

  # Keep the previous summary around for comparison before this run
  # overwrites it. (Guarded with an if, not `[[ ]] &&`: under `set -e`, a
  # short-circuited `&&` when the file doesn't exist yet -- the first-ever
  # run for this package -- returns a nonzero status that would abort the
  # whole script.)
  if [[ -f "$summary_json" ]]; then
    cp "$summary_json" "$summary_json_prev"
  fi

  set +e
  gremlins unleash --workers "$MUTATION_WORKERS" -o "$result_json_tmp" "./$pkg" \
    >"$MUTATION_STATE_DIR/last-$label.log" 2>&1
  status=$?
  set -e

  if [[ ! -s "$result_json_tmp" ]]; then
    echo "=== $(date -u +%FT%TZ) $label produced no results (gremlins exit $status) -- see $MUTATION_STATE_DIR/last-$label.log ===" >&2
    continue
  fi
  mv "$result_json_tmp" "$result_json"

  python3 "$SCRIPT_DIR/summarize.py" "$label" >"$summary_json"

  "$SCRIPT_DIR/notify-summary.sh" "$label" "$summary_json" "${summary_json_prev:-}"

  if [[ -n "${min_efficacy:-}" ]]; then
    if ! python3 -c 'import json, sys
eff = json.load(open(sys.argv[1])).get("test_efficacy_pct")
sys.exit(0 if eff is not None and eff >= float(sys.argv[2]) else 1)' "$summary_json" "$min_efficacy"; then
      echo "=== $(date -u +%FT%TZ) $label is below its efficacy floor ${min_efficacy}% -- see $summary_json ===" >&2
      below_floor=1
    fi
  fi
done <<<"$PACKAGES"

echo "=== $(date -u +%FT%TZ) mutation-testing run complete ==="
exit "$below_floor"
