#!/bin/bash
# cli-command-census.sh — CI entry point for FINISH-SPLIT step 3
# (docs/cli-split-inventory.md §9). The actual logic (walking the old CLI's live
# cobra tree, the commandCensus classification map) lives in
# internal/cli/command_census_test.go, where it has direct access to the
# package's unexported rootCmd — this is a thin wrapper, not a fork.
#
# Fails if any leaf command in the old CLI is unmapped (a new command added with
# no classification) or if a mapped entry no longer corresponds to a real command
# (a stale claim). A tracked-but-undecided command (censusGap) does not fail this
# check — see the test file's own doc comment for why, and TestNoGapsRemain for
# the separate, stricter gate PR 14 / Phase 5 needs.
#
# Usage:
#   ./scripts/cli-command-census.sh              # CI check
#   ./scripts/cli-command-census.sh --regen      # regenerate docs/cli-split-inventory-census.md
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "${1:-}" = "--regen" ]; then
  KEYORIX_CENSUS_REGEN=1 go -C "$REPO_ROOT" test ./internal/cli/ -run TestCLICommandCensus -v
else
  go -C "$REPO_ROOT" test ./internal/cli/ -run TestCLICommandCensus -v
fi
