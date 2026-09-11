#!/usr/bin/env bash
# Per-run fuzz logs that are never overwritten, plus an off-box copy of every
# failing run's log on a single GitHub tracking issue. Sourced by
# scripts/fuzzing/run-rotation.sh — not meant to be executed on its own.
# (Same design as dashdiag's scripts/fuzz-runlog.sh.)
#
# Why this exists: the rig used to write each target's output to
# $NOTIFIED_STATE_DIR/last-<Target>.log, overwritten by the same target's next
# run. On the VCD rig FuzzCombineKEK exited 1 about 15 times in 2026-09 and
# FuzzVerifyReceipt about 20 times in July-August, and not one of those runs'
# output survived to be read — the next run had already replaced it. A log
# that is gone is a finding nobody can triage.
#
# Layout under $FUZZ_LOG_DIR (default $NOTIFIED_STATE_DIR/logs, which the
# systemd unit already allows writes to):
#   <Target>/<UTC start>_<commit>_<pid>.log              while the run is going
#                                                        (-2, -3... if that name was taken)
#   <Target>/<UTC start>_<commit>_<pid>_exit<N>.log.gz   once it has finished
#   <Target>/latest.log.gz -> the newest finished run
#   .pending-post/<file>.gz__<Target> -> failing runs not yet copied to GitHub
#                                         (named so the queue sorts oldest first)
#
# Nothing here prunes. The `fuzz: elapsed ...` progress lines that make up
# most of a log compress very well; a year of continuous fuzzing is on the
# order of 100 MB of gzip.
#
# The box is disposable (the VCD tenant is temporary), so "kept forever on the
# box" is not kept forever. Every failing run is therefore also posted as a
# comment on one tracking issue in this repo — including runs
# notify-on-crash.sh classifies as "infra failure, no reproducer" and stays
# silent about. Posting is queued: if GitHub is unreachable or GH_TOKEN lacks
# the Issues permission, the entry stays in .pending-post and is retried after
# every later target, a few at a time.
#
# Everything is best-effort. A logging or posting problem must never stop the
# fuzzing loop, so failures are reported on stderr and swallowed.

FUZZ_LOG_DIR="${FUZZ_LOG_DIR:-${NOTIFIED_STATE_DIR:-$HOME/.keyorix-fuzz}/logs}"
# Queue entries are symlinks to the logs, so the directory must be absolute.
case "$FUZZ_LOG_DIR" in /*) ;; *) FUZZ_LOG_DIR="$PWD/$FUZZ_LOG_DIR" ;; esac
# Set to 0 to keep logs on the box only.
FUZZ_POST_FAILURES="${FUZZ_POST_FAILURES:-1}"
FUZZ_ISSUE_TITLE="${FUZZ_ISSUE_TITLE:-fuzz rig: failing-run logs}"
# GitHub caps a comment body at 65,536 characters; leave room for the header.
FUZZ_POST_MAX_BYTES="${FUZZ_POST_MAX_BYTES:-50000}"
# Queue entries posted per call, so a backlog drains over several targets
# instead of stalling one gap between targets.
FUZZ_POST_BATCH="${FUZZ_POST_BATCH:-5}"

RUNLOG=""
RUNLOG_FINAL=""
RUNLOG_NAME=""
RUNLOG_START_EPOCH=0

# runlog_start NAME PKG FUZZTIME — opens a fresh log for one run and sets
# $RUNLOG. Append to it (>>), never truncate it (>): the header is already
# there.
runlog_start() {
  local name="$1" pkg="$2" fuzztime="$3" dir commit stem base n
  RUNLOG_NAME="$name"
  RUNLOG_FINAL=""
  RUNLOG_START_EPOCH="$(date -u +%s)"
  dir="$FUZZ_LOG_DIR/$name"
  if ! mkdir -p "$dir"; then
    # Still give the caller somewhere to write, so the run itself goes ahead.
    RUNLOG="$(mktemp "${TMPDIR:-/tmp}/fuzz-$name.XXXXXX.log")"
    echo "runlog: cannot create $dir — this run's log is only at $RUNLOG" >&2
    return 0
  fi
  commit="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  # Timestamp, commit and PID already make this unique for any real run
  # (targets fuzz for minutes to hours), but a target that dies instantly —
  # a build failure, say — can come round again within the same second.
  # Never reuse a stem that any existing log (finished or not) already has.
  stem="$dir/$(date -u +%Y%m%dT%H%M%SZ)_${commit}_$$"
  base="$stem"
  n=1
  while compgen -G "${base}[._]*" >/dev/null; do
    n=$((n + 1))
    base="${stem}-$n"
  done
  RUNLOG="$base.log"
  {
    echo "# host:     $(hostname)"
    echo "# target:   $name"
    echo "# package:  $pkg"
    echo "# commit:   $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "# go:       $(go version 2>/dev/null || echo unknown)"
    echo "# fuzztime: $fuzztime"
    echo "# started:  $(date -u +%FT%TZ)"
    echo "#"
  } >>"$RUNLOG" || echo "runlog: could not write header to $RUNLOG" >&2
  return 0
}

# runlog_finish STATUS — stamps the result, renames the log to carry its exit
# status, gzips it, points latest.log.gz at it, and queues it for GitHub if
# the run failed. Sets $RUNLOG_FINAL to the path the log now lives at.
runlog_finish() {
  local status="$1" final dir
  RUNLOG_FINAL="$RUNLOG"
  [[ -n "$RUNLOG" && -f "$RUNLOG" ]] || return 0
  {
    echo "#"
    echo "# finished: $(date -u +%FT%TZ)"
    echo "# duration: $(($(date -u +%s) - RUNLOG_START_EPOCH))s"
    echo "# exit:     $status"
  } >>"$RUNLOG" || echo "runlog: could not write footer to $RUNLOG" >&2

  # Only logs under $FUZZ_LOG_DIR are renamed and kept; the mktemp fallback
  # from runlog_start is left where it is.
  case "$RUNLOG" in "$FUZZ_LOG_DIR"/*) ;; *) return 0 ;; esac

  final="${RUNLOG%.log}_exit${status}.log"
  # -n: never replace an existing file. gzip also refuses to overwrite an
  # existing .gz without -f, so neither step can destroy an older log.
  if mv -n "$RUNLOG" "$final" && [[ ! -e "$RUNLOG" ]] && gzip -9n "$final"; then
    RUNLOG_FINAL="$final.gz"
  else
    echo "runlog: could not finalize $RUNLOG — left uncompressed" >&2
    [[ -f "$final" ]] && RUNLOG_FINAL="$final"
  fi
  dir="$(dirname "$RUNLOG_FINAL")"
  ln -sfn "$(basename "$RUNLOG_FINAL")" "$dir/latest.log.gz" 2>/dev/null || true

  if [[ "$status" -ne 0 && "$FUZZ_POST_FAILURES" == 1 ]]; then
    if mkdir -p "$FUZZ_LOG_DIR/.pending-post"; then
      ln -s "$RUNLOG_FINAL" "$FUZZ_LOG_DIR/.pending-post/$(basename "$RUNLOG_FINAL")__${RUNLOG_NAME}" ||
        echo "runlog: could not queue $RUNLOG_FINAL for GitHub" >&2
    fi
  fi
  return 0
}

# Prints the tracking issue's number, creating the issue on first use. The
# number is cached in a file rather than re-found by search each time: GitHub's
# search index lags new issues by up to a minute, which would open duplicates.
# To start a new one: close the issue and delete $FUZZ_LOG_DIR/.tracking-issue.
runlog_tracking_issue() {
  local cache="$FUZZ_LOG_DIR/.tracking-issue" num
  if [[ -s "$cache" ]]; then
    cat "$cache"
    return 0
  fi
  # List endpoint, not search (see above). The title is a fixed string with no
  # quotes in it, so embedding it in the jq program is safe.
  num="$(gh issue list --state open --limit 1000 --json number,title \
    --jq "[.[] | select(.title == \"$FUZZ_ISSUE_TITLE\")] | sort_by(.number) | .[0].number // empty")" || return 1
  if [[ -z "$num" ]]; then
    num="$(gh issue create --title "$FUZZ_ISSUE_TITLE" --body "Opened automatically by the continuous-fuzzing rig (scripts/fuzzing/run-rotation.sh).

Every fuzz run that exits non-zero posts its log here as a comment — whether or not it produced a \`testdata/fuzz\` reproducer, and whether or not notify-on-crash.sh opened a \`fuzz(crash)\` PR for it. This issue is the durable record of *every* failure, including the ones that turn out to be harness flakes or infra failures, so none of them has to be triaged from a log that no longer exists.

Full logs stay on the rig under \`\$FUZZ_LOG_DIR/<Target>/\`, gzipped and never overwritten. See scripts/fuzzing/README.md." | grep -oE '[0-9]+$')" || return 1
  fi
  [[ -n "$num" ]] || return 1
  printf '%s\n' "$num" >"$cache"
  printf '%s\n' "$num"
}

# runlog_post_one ISSUE QUEUE_ENTRY — posts one queued log. Returns non-zero
# if it could not, so the caller stops and retries later.
runlog_post_one() {
  local issue="$1" entry="$2" gz name header host status sig_line sig_hash body_file excerpt
  gz="$(readlink "$entry")"
  if [[ ! -f "$gz" ]]; then
    echo "runlog: queued log $gz no longer exists — dropping it from the queue" >&2
    return 0
  fi
  # The log's directory is named after its target.
  name="$(basename "$(dirname "$gz")")"
  header="$(zcat -f "$gz" | grep -E '^# [a-z]+: ' || true)"
  host="$(sed -n 's/^# host: *//p' <<<"$header")"
  status="$(sed -n 's/^# exit: *//p' <<<"$header")"
  sig_line="$(zcat -f "$gz" | grep -m1 -E 'FAIL|panic:' || true)"
  # Same hash notify-on-crash.sh uses for its dedup marker
  # (notified-<Func>-<hash>), so a comment here can be matched to it.
  sig_hash="$(printf '%s' "${sig_line:-unknown}" | sha256sum | cut -c1-16)"
  # Drop the progress ticker and our own header lines (not every line starting
  # with "# ": Go prints build errors as "# <import path>").
  excerpt="$(zcat -f "$gz" | grep -vE '^(fuzz: elapsed|# [a-z]+: |#$)' | tail -c "$FUZZ_POST_MAX_BYTES" || true)"

  body_file="$(mktemp)"
  {
    echo "### \`$name\` exited ${status:-?} on \`${host:-unknown host}\`"
    echo
    echo '```'
    echo "$header"
    echo '```'
    echo
    echo "**Failure signature:** \`${sig_line:-none found}\` (hash \`$sig_hash\`)"
    echo
    echo "**Full log on the rig:** \`$gz\`"
    echo
    echo "<details><summary>Log excerpt (fuzz progress lines removed; last ${FUZZ_POST_MAX_BYTES} bytes)</summary>"
    echo
    echo '~~~~~~~~'
    echo "$excerpt"
    echo '~~~~~~~~'
    echo
    echo '</details>'
  } >"$body_file"

  if gh issue comment "$issue" --body-file "$body_file" >/dev/null; then
    rm -f "$body_file"
    return 0
  fi
  rm -f "$body_file"
  return 1
}

# Posts up to $FUZZ_POST_BATCH queued failing-run logs to the tracking issue.
# Removes each queue entry only once its comment is confirmed posted.
runlog_post_pending() {
  [[ "$FUZZ_POST_FAILURES" == 1 ]] || return 0
  local queue="$FUZZ_LOG_DIR/.pending-post" issue entry posted=0
  local -a entries=()
  [[ -d "$queue" ]] || return 0
  shopt -s nullglob
  entries=("$queue"/*)
  shopt -u nullglob
  [[ "${#entries[@]}" -gt 0 ]] || return 0

  if ! issue="$(runlog_tracking_issue)"; then
    echo "runlog: GitHub unreachable or issue not writable — ${#entries[@]} failing-run log(s) still queued in $queue" >&2
    return 0
  fi
  for entry in "${entries[@]}"; do
    [[ "$posted" -lt "$FUZZ_POST_BATCH" ]] || break
    if runlog_post_one "$issue" "$entry"; then
      rm -f "$entry"
      posted=$((posted + 1))
    else
      echo "runlog: could not post $(readlink "$entry") to issue #$issue — will retry after the next target" >&2
      break
    fi
  done
  return 0
}
