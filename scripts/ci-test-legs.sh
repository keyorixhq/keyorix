#!/usr/bin/env bash
# scripts/ci-test-legs.sh — single source of truth for which Go packages each
# CI test-suite matrix leg (.github/workflows/ci.yml) runs, and which packages
# are deliberately excluded from every leg, with a reason.
#
# G80 campaign, C5: before this file existed, the exclusion patterns lived
# only as bare `grep -v` flags in ci.yml with a comment pointing at
# `git log -S` for the reason -- exactly the shape that let server/http sit
# excluded, with no leg anywhere, for ~4 months, invisible to anyone not
# already reading that file's history. This file is sourced by BOTH the
# test-suite matrix step and the leg-completeness assertion job, so the two
# can never silently drift apart -- a package pinned to a leg here is pinned
# for both; a pattern excluded here is excluded for both.
#
# Not executable on its own: `source` this file, then call its functions.

# exclusion_entries: one per line, pipe-delimited:
#   <go-list-suffix-regex>|<kind>|<reason>|<issue>|<date-added:YYYY-MM-DD>
#
# kind is one of:
#   TEMPORARY -- a real gap meant to close. Subject to the 30-day freshness
#     check in ci.yml: an entry older than 30 days fails CI outright, so a
#     stale exclusion cannot simply sit forever unnoticed the way the
#     pre-C5 bare grep -v list did.
#   PERMANENT -- structurally correct forever (generated code with nothing
#     to test). No fix will ever "land" for this, so it is exempt from the
#     freshness check.
#   SHARDED -- NOT a coverage gap. The package runs, just via its own
#     dedicated matrix leg(s) below (server/http/handlers -> handlers-1..4)
#     rather than through root_base()'s catch-all. Excluded from root_base's
#     package list (so it isn't ALSO run there, doubling the work) but
#     included back into the completeness union via its dedicated leg(s).
#     Exempt from the freshness check for the same reason as PERMANENT: it
#     is not a gap to close.
#
# date-added is when an entry was captured in THIS structured, enforced
# table -- not necessarily when the underlying exclusion was first added to
# ci.yml. The three TEMPORARY entries below trace back to a bare `grep -v`
# added 2026-04-27 (commit 7ccb7dda) -- see their linked issues for that
# history -- but are dated here 2026-08-23, the day this ratchet was
# introduced (G80 C5). Back-dating them to 2026-04-27 would fail the
# freshness check on the PR that introduces the check itself, which is not
# the failure mode this check exists to catch (a NEW exclusion sitting
# unreviewed for 30+ days going forward); the ~4-month-old debt itself is
# not hidden -- it's on record in #1533/#1534/#1535 and in this comment.
exclusion_entries() {
  cat <<'EOF'
internal/cli$|TEMPORARY|TestRemoteCLIIntegration/TestLocalToRemoteSwitching require a running server (originally excluded 2026-04-27, commit 7ccb7dda)|#1533|2026-08-23
internal/storage/remote|TEMPORARY|TestRemoteStorage_Health times out (originally excluded 2026-04-27, commit 7ccb7dda)|#1534|2026-08-23
server/http$|TEMPORARY|TestSharingHTTPIntegration/TestHTTPServerErrorScenarios -- G80 campaign C4 target (originally excluded 2026-04-27, commit 7ccb7dda)|#1535|2026-08-23
server/http/handlers$|SHARDED|runs in its own dedicated handlers-1..4 matrix legs below|n/a|2026-04-27
server/proto/pb$|PERMANENT|auto-generated protobuf code (DO NOT EDIT), no tests to write|n/a|2026-07-18
EOF
}

# exclusion_patterns: just the regex column, one per line -- the set of
# patterns root_base() excludes from the root/core legs entirely (every kind:
# a SHARDED package must not ALSO run via root_base's catch-all, even though
# it runs elsewhere).
exclusion_patterns() {
  exclusion_entries | cut -d'|' -f1
}

# never_run_patterns: exclusion_patterns filtered to kinds that mean "this
# package runs in NO leg, anywhere" (TEMPORARY, PERMANENT) -- excludes
# SHARDED, which does run, just not via root_base. This is the set the
# leg-completeness assertion subtracts from `go list ./...`.
never_run_patterns() {
  exclusion_entries | awk -F'|' '$2 != "SHARDED" { print $1 }'
}

# root_base: every package eligible for the root-N/core legs -- go list
# minus every exclusion pattern (all kinds; a SHARDED package must not
# double-run here even though it's covered elsewhere).
root_base() {
  local args=()
  while IFS= read -r pattern; do
    args+=(-e "$pattern")
  done < <(exclusion_patterns)
  go list ./... | grep -v "${args[@]}"
}

# Pinned "heavy" package lists for root-1/2/3 and core (bin-packed by
# measured per-package time -- see ci.yml's own comments for the
# measurement history). Keep these four lists in sync with root-4's
# implicit catch-all below: a package listed in one of these must not
# ALSO be pinned to another, and root-4 is defined as everything else.
root_1_pkgs() {
  cat <<'EOF'
github.com/keyorixhq/keyorix/internal/encryption
github.com/keyorixhq/keyorix/server/grpc/services
github.com/keyorixhq/keyorix/internal/cli/invite
github.com/keyorixhq/keyorix/internal/cli/group
github.com/keyorixhq/keyorix/internal/cli/run
github.com/keyorixhq/keyorix/internal/crypto
github.com/keyorixhq/keyorix/server/grpc
github.com/keyorixhq/keyorix/internal/testhelper
github.com/keyorixhq/keyorix/internal/cli/accessreview
github.com/keyorixhq/keyorix/internal/cli/anomalies
github.com/keyorixhq/keyorix/internal/cli/auth
github.com/keyorixhq/keyorix/internal/bundle
github.com/keyorixhq/keyorix/internal/rotation
github.com/keyorixhq/keyorix/internal/cli/license
github.com/keyorixhq/keyorix/internal/cli/config
github.com/keyorixhq/keyorix/cmd/validate-translations
github.com/keyorixhq/keyorix/internal/startup
github.com/keyorixhq/keyorix/internal/di
github.com/keyorixhq/keyorix/server/webui
EOF
}

root_2_pkgs() {
  cat <<'EOF'
github.com/keyorixhq/keyorix/internal/cli/user
github.com/keyorixhq/keyorix/internal/cli/encryption
github.com/keyorixhq/keyorix/internal/storage
github.com/keyorixhq/keyorix/internal/cli/share
github.com/keyorixhq/keyorix/server/grpc/interceptors
github.com/keyorixhq/keyorix/internal/cli/common
github.com/keyorixhq/keyorix/internal/cli/hygiene
github.com/keyorixhq/keyorix/internal/cli/sod
github.com/keyorixhq/keyorix/internal/cli/breakglass
github.com/keyorixhq/keyorix/internal/cli/audit
github.com/keyorixhq/keyorix/internal/saml
github.com/keyorixhq/keyorix/internal/i18n
github.com/keyorixhq/keyorix/internal/notary
github.com/keyorixhq/keyorix/internal/securefiles
github.com/keyorixhq/keyorix/internal/trust
github.com/keyorixhq/keyorix/internal/license
github.com/keyorixhq/keyorix/internal/cli/trust
github.com/keyorixhq/keyorix/internal/crypto/awskms
github.com/keyorixhq/keyorix/internal/utils/safeconv
EOF
}

root_3_pkgs() {
  cat <<'EOF'
github.com/keyorixhq/keyorix/server/tools
github.com/keyorixhq/keyorix/internal/cli/machine
github.com/keyorixhq/keyorix/server
github.com/keyorixhq/keyorix/internal/cli/rbac
github.com/keyorixhq/keyorix/internal/cli/project
github.com/keyorixhq/keyorix/internal/cli/status
github.com/keyorixhq/keyorix/internal/notifychan
github.com/keyorixhq/keyorix/internal/cli/risk
github.com/keyorixhq/keyorix/internal/cli/rotation
github.com/keyorixhq/keyorix/internal/cli/dynamic
github.com/keyorixhq/keyorix/internal/audit/siem
github.com/keyorixhq/keyorix/internal/mcp
github.com/keyorixhq/keyorix/internal/cli/bundle
github.com/keyorixhq/keyorix/server/validation
github.com/keyorixhq/keyorix/internal/connect
github.com/keyorixhq/keyorix/internal/config
github.com/keyorixhq/keyorix/internal/storage/models
github.com/keyorixhq/keyorix/internal/delivery
github.com/keyorixhq/keyorix/internal/core/storage
EOF
}

core_pkgs() {
  echo "github.com/keyorixhq/keyorix/internal/core"
}

# root_4_pkgs: the dynamic catch-all -- every root_base() package not pinned
# to root-1/2/3/core above, so a newly added package always lands somewhere
# (root-4) rather than silently running nowhere.
root_4_pkgs() {
  local pinned
  pinned=$(cat <(root_1_pkgs) <(root_2_pkgs) <(root_3_pkgs) <(core_pkgs) | sort -u)
  comm -23 <(root_base | sort -u) <(echo "$pinned")
}

# handlers_pkg: the single package every handlers-1..4 leg shards by test
# name, not by package -- for leg-completeness purposes (which only cares
# about PACKAGE coverage) all four legs collectively cover exactly this one
# package.
handlers_pkg() {
  echo "github.com/keyorixhq/keyorix/server/http/handlers"
}

# pkgs_for_leg: package list for a given leg name, space/newline-separated.
# Matches the case statement the test-suite matrix step uses to pick $pkgs.
pkgs_for_leg() {
  case "$1" in
    root-1) root_1_pkgs ;;
    root-2) root_2_pkgs ;;
    root-3) root_3_pkgs ;;
    core) core_pkgs ;;
    root-4) root_4_pkgs ;;
    handlers-1|handlers-2|handlers-3|handlers-4) handlers_pkg ;;
    *) echo "pkgs_for_leg: unknown leg '$1'" >&2; return 1 ;;
  esac
}

# all_leg_names: every matrix leg, in the same order ci.yml's matrix.include
# declares them. Kept here too so the completeness check enumerates exactly
# the legs that exist, not a hand-copied list that can drift from the matrix.
all_leg_names() {
  cat <<'EOF'
root-1
root-2
root-3
root-4
core
handlers-1
handlers-2
handlers-3
handlers-4
EOF
}

# run_filter_for_shard: builds a `go test -run` regex selecting roughly 1/N
# of a single package's top-level tests, by (sorted test name index) mod N --
# the mechanism handlers-1..4 already uses. Shared here so any future
# by-test-name-sharded leg (not just handlers) reuses the identical, already-
# proven splitting logic instead of a second hand-copied implementation.
run_filter_for_shard() {
  local pkg="$1" shard="$2" n="$3"
  local names selected
  names=$(go test -list '^Test' "$pkg" | grep -v '^ok\b' | sort)
  selected=$(echo "$names" | awk -v n="$n" -v s="$shard" 'NR % n == (s - 1)')
  printf '^(%s)$' "$(echo "$selected" | paste -sd '|')"
}

# check_exclusion_freshness: fails (nonzero exit, one line per offender on
# stdout) if any TEMPORARY exclusion_entries row is more than 30 days old.
# PERMANENT/SHARDED rows are exempt -- there is no fix to land for either, so
# "how long has this sat here" is not a meaningful signal for them. This is
# deliberately a hard failure, not a warning: a warning is exactly what the
# pre-C5 bare `grep -v` list amounted to in practice (a comment nobody
# re-reads), which is how server/http sat excluded with no leg for ~4 months
# unnoticed.
check_exclusion_freshness() {
  local today_epoch failed=0
  today_epoch=$(date -u -d "$(date -u +%Y-%m-%d)" +%s)
  while IFS='|' read -r pattern kind reason issue added; do
    [ "$kind" = "TEMPORARY" ] || continue
    local added_epoch age_days
    added_epoch=$(date -u -d "$added" +%s)
    age_days=$(( (today_epoch - added_epoch) / 86400 ))
    if [ "$age_days" -gt 30 ]; then
      echo "STALE EXCLUSION (${age_days}d > 30d budget): $pattern -- $reason ($issue, added $added)"
      failed=1
    fi
  done < <(exclusion_entries)
  return $failed
}

# assert_leg_completeness: fails (nonzero exit, listing every offending
# package on stdout) if any package in `go list ./...` is covered by NEITHER
# the exclusion table (never_run_patterns -- TEMPORARY/PERMANENT only; a
# SHARDED package must still be covered by its own leg to pass) NOR any CI
# test-suite leg's package list. This is the guard against a package
# silently landing in zero legs, the exact failure mode that let
# server/http go untested for ~4 months with nothing red anywhere.
assert_leg_completeness() {
  local never_args=()
  while IFS= read -r p; do never_args+=(-e "$p"); done < <(never_run_patterns)
  local target actual missing
  target=$(go list ./... | grep -v "${never_args[@]}" | sort -u)
  actual=$(
    while IFS= read -r leg; do
      pkgs_for_leg "$leg"
    done < <(all_leg_names) | sort -u
  )
  missing=$(comm -23 <(echo "$target") <(echo "$actual"))
  if [ -n "$missing" ]; then
    echo "The following package(s) are covered by NO CI test-suite leg and are not in the exclusion table (scripts/ci-test-legs.sh):"
    echo "$missing"
    return 1
  fi
  echo "OK: every non-excluded package is covered by at least one CI test-suite leg."
  return 0
}
