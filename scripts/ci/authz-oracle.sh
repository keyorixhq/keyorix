#!/usr/bin/env bash
# authz-oracle.sh plan BASE [HEAD]   print the plan (mode=, ops=, reasons)
# authz-oracle.sh run MODE OPS        run the strict authzdiff sweep for a plan
#
# The PR gate that ties permission-check code to the server/authzdiff oracle
# model (AUTHZ-MODEL-GUARD-1, KFZ-2026-092: #4332 tightened IssueMachineToken,
# the model was not updated, and only a fuzz lane noticed, hours later). ci.yml
# runs `plan` in fuzz-plan and `run` in the authz-oracle job; the same two
# commands reproduce a CI verdict locally:
#
#   scripts/ci/authz-oracle.sh plan origin/main
#   scripts/ci/authz-oracle.sh run ops machine.token.issue
#
# run executes TestAuthzDiffSweep with AUTHZDIFF_SWEEP=1 AUTHZDIFF_STRICT=1
# (every op x principal x target x arg x generated custom role; any case the
# partition cannot explain fails) restricted to OPS for mode ops, plus the
# FuzzAuthzDiff seed corpus as plain tests. It then checks the verbose log with
# `authzgate check-log`: AUTHZDIFF_OPS silently skips an unknown op name, so a
# green run that swept nothing, or skipped a planned op, is a failure here.
# A mode-none plan runs nothing.
#
# Env: AUTHZGATE_BIN (prebuilt authzgate; default: go build into $TMPDIR),
# AUTHZ_ORACLE_LOG (verbose go test log; default: $TMPDIR/authz-oracle.log).
set -euo pipefail

gate_bin() {
  if [ -n "${AUTHZGATE_BIN:-}" ]; then
    printf '%s\n' "$AUTHZGATE_BIN"
    return
  fi
  local bin="${TMPDIR:-/tmp}/authzgate"
  go build -o "$bin" ./scripts/ci/authzgate
  printf '%s\n' "$bin"
}

case "${1:-}" in
  plan)
    base=${2:?usage: authz-oracle.sh plan BASE [HEAD]}
    head=${3:-HEAD}
    "$(gate_bin)" plan -base "$base" -head "$head"
    ;;
  run)
    mode=${2:?usage: authz-oracle.sh run MODE OPS}
    ops=${3:-}
    case "$mode" in
      none) echo "authz-oracle: no permission-check code changed; nothing to run"; exit 0 ;;
      ops) [ -n "$ops" ] || { echo "authz-oracle: mode ops with an empty op list" >&2; exit 1; } ;;
      full) ops="" ;;
      *) echo "authz-oracle: unknown mode '$mode'" >&2; exit 2 ;;
    esac
    bin="$(gate_bin)"
    log="${AUTHZ_ORACLE_LOG:-${TMPDIR:-/tmp}/authz-oracle.log}"
    echo "authz-oracle: mode=$mode ops=${ops:-<all>}"
    status=0
    AUTHZDIFF_SWEEP=1 AUTHZDIFF_STRICT=1 AUTHZDIFF_OPS="$ops" \
      go test ./server/authzdiff -run '^(TestAuthzDiffSweep|FuzzAuthzDiff)$' -count=1 -v -timeout 40m \
      > "$log" 2>&1 || status=$?
    # The sweep's own summary and every case it could not explain.
    grep -E 'sweep: [0-9]+ cases|partition of|DISAGREEMENT \[unexplained\]|UNCALIBRATED|UNEXPLAINED|^(--- FAIL|FAIL|ok|panic)' "$log" | head -200 || true
    if [ "$mode" = full ]; then
      "$bin" check-log -full -ops "" "$log"
    else
      "$bin" check-log -ops "$ops" "$log"
    fi
    if [ "$status" -ne 0 ]; then
      echo "authz-oracle: the strict sweep failed: the authzdiff model and the product disagree (or the harness broke)."
      echo "If this PR changed an authorization rule on purpose, update the reference model in server/authzdiff (model_test.go) in the same PR."
    fi
    exit "$status"
    ;;
  *)
    echo "usage: authz-oracle.sh plan BASE [HEAD] | run MODE OPS" >&2
    exit 2
    ;;
esac
