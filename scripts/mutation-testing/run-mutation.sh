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
# "<go-package-path>|<label>[|<timeout-coefficient>[|<min-efficacy-pct>]]".
# The optional third field is passed to gremlins as --timeout-coefficient. gremlins sizes its
# per-mutant timeout from the time of the coverage-gathering run, and for a package whose tests
# are fast but whose per-mutant build is not (internal/saml: ~0.3 s of tests, ~1 s to rebuild
# against crewjam/saml) the default timeout expires on most mutants; they come back TIMED OUT,
# which summarize.py counts as neither killed nor lived, so the report shows no usable result.
# Leave it empty for packages that do not need it: a larger coefficient also makes a genuinely
# hanging mutant take that much longer to time out.
#
# Widen this deliberately, one package at a time, as each is brought into good
# shape -- see .github's retired mutation-testing.yml (superseded by this
# script) for the reasoning on why this starts scoped to few packages
# instead of the whole repo.
#
# The optional fourth field is an absolute floor, measured when the package was
# brought in (MUTANT-SEC-1, gremlins --workers 1; leave the third field empty
# when no timeout coefficient is needed). Falling below it fails the run at the
# end, in addition to the relative-regression notice from notify-summary.sh.
# The remaining survivors in these packages are equivalent mutants (see the item
# commits), so the floor is the measured value, not 100.
#
# The optional fifth field is the floor for a run with KEYORIX_TEST_PG_DSN set
# (one database per package, MUTATION_WORKERS=1): the PostgreSQL-only tests
# then run and cover mutants the run without a DSN reports as not covered, so
# the two efficacies differ. With a DSN set it replaces the fourth field; a
# package without one keeps the fourth (its result does not depend on the DSN,
# or its Postgres floor is not measured yet).
#
# A quoted heredoc, not a double-quoted string: the comment lines below quote
# code (backticks, double quotes), which a double-quoted string runs as command
# substitutions -- under set -e the assignment then exited 127 before any
# package was measured (FENCE-VERIFY-1; run_mutation_packages_test.py).
PACKAGES=$(cat <<'EOF'
internal/core|core
internal/storage/store|storage-store
internal/keyfiles|keyfiles||93.55
internal/securefiles|securefiles||98.31
internal/recoverykey|recoverykey||82.35
internal/evidencesink|evidencesink||100
# internal/saml: efficacy 97.70% (85 killed, 2 equivalent survivors), 21 not covered; needs the timeout coefficient (see above)
internal/saml|saml|40
# internal/secretenv: efficacy 100% (31 killed), 4 not covered (switch case expressions, pinned by a truth table)
internal/secretenv|secretenv
# internal/netutil (egress and SSRF guards): efficacy 100% (35 killed), no survivors, nothing not covered
internal/netutil|netutil||100
# internal/auditverify (the run includes internal/auditverify/anchorbundle): efficacy 99.55% (223 killed, 1 equivalent survivor,
# db.go:56 sql.Open("pgx") never errors at open), 16 not covered (switch case expressions and string-constant concatenations that
# gremlins cannot instrument), 4 timed out (high-water mutants in verify.go that hang, counted as neither killed nor lived)
internal/auditverify|auditverify||99.55
# internal/serverguard: efficacy 100% (35 killed, measured without KEYORIX_TEST_PG_DSN), 31 not covered: the PostgreSQL-only
# paths (keyinit.go and the advisory-lock/pooler code), whose tests need a real Postgres
# With a DSN (FENCE-VERIFY-1): the survivors are the release paths' 10 s unlock timeouts, the log-only branches of a failed
# explicit unlock/ROLLBACK and keyinit.go's lock-lost error detail; none decides whether a lock is held
internal/serverguard|serverguard||100|88.89
# internal/solewriter: efficacy 99.26% (134 killed, 1 equivalent survivor: tracker.go:269 `len(t.UpdateIgnores) > 0`, because onlySets
# with no columns is always false), 250 not covered: the PostgreSQL-backed paths (fence install, poller, lock), whose tests need a real Postgres
internal/solewriter|solewriter||99.26
# internal/core/rules: efficacy 98.06% (101 killed, 2 equivalent survivors: secret_value_policy.go:44 `MinLength > 0` and
# password_policy.go:172 `at > 0`, each shadowed by a later length check), 4 not covered (the `iota + 1` constant and two switch case expressions)
internal/core/rules|rules||98.06
# internal/identity: efficacy 100% (3 killed), no survivors, nothing not covered
internal/identity|identity||100
EOF
)

cd "$KEYORIX_REPO"

echo "=== $(date -u +%FT%TZ) pulling latest main ==="
git fetch origin main --quiet
git checkout main --quiet
git reset --hard origin/main --quiet

below_floor=0

while IFS='|' read -r pkg label timeout_coef min_efficacy min_efficacy_pg; do
  [[ -z "$pkg" ]] && continue
  case "$pkg" in \#*) continue ;; *) ;; esac
  if [[ -n "${KEYORIX_TEST_PG_DSN:-}" && -n "${min_efficacy_pg:-}" ]]; then
    min_efficacy="$min_efficacy_pg"
  fi
  timeout_args=()
  if [[ -n "${timeout_coef:-}" ]]; then
    timeout_args=(--timeout-coefficient "$timeout_coef")
  fi

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
  gremlins unleash --workers "$MUTATION_WORKERS" ${timeout_args[@]+"${timeout_args[@]}"} -o "$result_json_tmp" "./$pkg" \
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
