#!/usr/bin/env bash
# Tests for scripts/fuzzing/runlog.sh. Runs with fake `go` and `gh` on PATH, so
# it needs no network, no Go toolchain and no GitHub token:
#
#   bash scripts/fuzzing/runlog_test.sh
#
# Runs under the same `set -euo pipefail` as run-rotation.sh, because the
# property that matters most is that nothing in the library can kill the
# fuzzing loop when GitHub or the disk misbehaves.
#
# Each check is a single-quoted expression that check() evals, so its
# variables expand when the check runs — which SC2016/SC2034 can't see.
# shellcheck disable=SC2016,SC2034
set -euo pipefail

LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runlog.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/repo"
# gh stand-in. FAKE_GH=fail makes every call fail (GitHub unreachable).
# `issue comment` saves each body so the test can inspect what was posted.
cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_GH_DIR/calls"
[[ "${FAKE_GH:-ok}" == fail ]] && { echo "gh: could not resolve host" >&2; exit 1; }
case "$1 $2" in
  "issue list") echo "${FAKE_GH_EXISTING:-}" ;;
  "issue create") echo "https://github.com/example/repo/issues/42" ;;
  "issue comment")
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --body-file ]]; then
        n=$(ls "$FAKE_GH_DIR" | grep -c '^body' || true)
        cp "$2" "$FAKE_GH_DIR/body$n"
      fi
      shift
    done ;;
esac
EOF
printf '#!/usr/bin/env bash\necho "go version go1.26.4 linux/amd64"\n' >"$WORK/bin/go"
chmod +x "$WORK/bin/gh" "$WORK/bin/go"
export PATH="$WORK/bin:$PATH"
export FAKE_GH_DIR="$WORK/gh"
mkdir -p "$FAKE_GH_DIR"

cd "$WORK/repo"
git init -q
git -c user.email=t@t -c user.name=t commit -q --allow-empty -m init

fails=0
pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

export FUZZ_LOG_DIR="$WORK/logs"
# shellcheck source=scripts/fuzzing/runlog.sh
source "$LIB"

# A run that produces the same kind of output a real one does.
fake_run() { # status
  echo "fuzz: elapsed: 0s, gathering baseline coverage: 0/12 completed"
  echo "fuzz: elapsed: 3s, execs: 1000 (333/sec), new interesting: 1 (total: 13)"
  if [[ "$1" -ne 0 ]]; then
    echo "# github.com/example/repo/internal/x"
    echo "--- FAIL: FuzzParseThing (901.14s)"
    echo "    context deadline exceeded"
    echo "FAIL"
  fi
}

# 1. A passing run is kept, compressed, stamped, and not queued.
runlog_start FuzzParseThing ./internal/x 15m
fake_run 0 >>"$RUNLOG"
runlog_finish 0
first="$RUNLOG_FINAL"
check "passing run is gzipped with its exit status in the name" '[[ "$first" == *_exit0.log.gz && -f "$first" ]]'
check "header records target and commit" 'zcat "$first" | grep -q "^# target:   FuzzParseThing" && zcat "$first" | grep -q "^# commit:   [0-9a-f]\{40\}"'
check "footer records exit status" 'zcat "$first" | grep -q "^# exit:     0"'
check "latest.log.gz points at the run" '[[ "$(readlink "$FUZZ_LOG_DIR/FuzzParseThing/latest.log.gz")" == "$(basename "$first")" ]]'
check "passing run is not queued for GitHub" '[[ ! -d "$FUZZ_LOG_DIR/.pending-post" ]] || [[ -z "$(ls -A "$FUZZ_LOG_DIR/.pending-post")" ]]'
first_sum="$(sha256sum "$first")"

# 2. The next run of the same target never touches the earlier log.
sleep 1
runlog_start FuzzParseThing ./internal/x 15m
fake_run 1 >>"$RUNLOG"
runlog_finish 1
second="$RUNLOG_FINAL"
check "second run gets its own file" '[[ "$second" != "$first" && -f "$second" && "$second" == *_exit1.log.gz ]]'
check "first run's log is byte-for-byte unchanged" '[[ "$(sha256sum "$first")" == "$first_sum" ]]'
check "latest.log.gz moved to the newer run" '[[ "$(readlink "$FUZZ_LOG_DIR/FuzzParseThing/latest.log.gz")" == "$(basename "$second")" ]]'
check "failing run is queued for GitHub" '[[ "$(ls "$FUZZ_LOG_DIR/.pending-post" | wc -l)" -eq 1 ]]'

# 2b. Same target, same exit status again: still a new file, old one intact.
# (This is the case the old last-<Target>.log scheme lost.)
second_sum="$(sha256sum "$second")"
sleep 1
runlog_start FuzzParseThing ./internal/x 15m
fake_run 1 >>"$RUNLOG"
runlog_finish 1
third="$RUNLOG_FINAL"
check "a repeat failure gets its own file" '[[ "$third" != "$second" && -f "$third" ]]'
check "the earlier failure's log is byte-for-byte unchanged" '[[ "$(sha256sum "$second")" == "$second_sum" ]]'
check "three runs, three logs" '[[ "$(ls "$FUZZ_LOG_DIR/FuzzParseThing"/*.log.gz | grep -vc latest)" -eq 3 ]]'
rm -f "$FUZZ_LOG_DIR/.pending-post/$(basename "$third")__FuzzParseThing"

# 3. GitHub unreachable: nothing is lost, nothing dies, the entry stays queued.
FAKE_GH=fail runlog_post_pending 2>/dev/null
check "post_pending survives an unreachable GitHub under set -e" 'true'
check "entry is still queued after a failed post" '[[ "$(ls "$FUZZ_LOG_DIR/.pending-post" | wc -l)" -eq 1 ]]'
check "no tracking issue cached after a failed post" '[[ ! -e "$FUZZ_LOG_DIR/.tracking-issue" ]]'

# 4. GitHub back: the issue is created once, the log is posted, the queue drains.
runlog_post_pending
check "tracking issue created and cached" '[[ "$(cat "$FUZZ_LOG_DIR/.tracking-issue")" == 42 ]]'
check "queue is empty after a successful post" '[[ -z "$(ls -A "$FUZZ_LOG_DIR/.pending-post")" ]]'
check "comment names target, exit status and host" 'grep -q "^### \`FuzzParseThing\` exited 1 on \`$(hostname)\`" "$FAKE_GH_DIR/body0"'
check "comment carries the failure signature" 'grep -q "FAIL: FuzzParseThing (901.14s)" "$FAKE_GH_DIR/body0"'
check "comment keeps Go build-error lines that start with \"# \"" 'grep -q "^# github.com/example/repo/internal/x" "$FAKE_GH_DIR/body0"'
check "comment drops the fuzz progress ticker" '! grep -q "^fuzz: elapsed" "$FAKE_GH_DIR/body0"'
check "posting never deletes the log itself" '[[ -f "$second" ]]'

# 5. The cached issue is reused: no second `issue create`.
for i in 1 2 3 4 5 6 7; do
  runlog_start "FuzzOther$i" ./internal/y 15m
  fake_run 1 >>"$RUNLOG"
  runlog_finish 1
done
runlog_post_pending
check "cached issue reused, never a second create" '[[ "$(grep -c "^issue create" "$FAKE_GH_DIR/calls")" -eq 1 ]]'
check "at most FUZZ_POST_BATCH (5) posted per call" '[[ "$(ls "$FUZZ_LOG_DIR/.pending-post" | wc -l)" -eq 2 ]]'
runlog_post_pending
check "backlog drains on the next call" '[[ -z "$(ls -A "$FUZZ_LOG_DIR/.pending-post")" ]]'

# 6. An existing open tracking issue is found instead of opening a new one.
rm -f "$FUZZ_LOG_DIR/.tracking-issue"
: >"$FAKE_GH_DIR/calls"
FAKE_GH_EXISTING=7 bash -c 'source "$0"; runlog_tracking_issue' "$LIB" >"$WORK/found"
check "existing issue found via the list endpoint" '[[ "$(cat "$WORK/found")" == 7 ]] && ! grep -q "^issue create" "$FAKE_GH_DIR/calls"'

# 7. A relative FUZZ_LOG_DIR is made absolute (queue entries are symlinks).
rel="$(FUZZ_LOG_DIR=rel-logs bash -c 'source "$0"; echo "$FUZZ_LOG_DIR"' "$LIB")"
check "relative FUZZ_LOG_DIR becomes absolute" '[[ "$rel" == "$PWD/rel-logs" ]]'

# 7b. With FUZZ_LOG_DIR unset, logs go under $NOTIFIED_STATE_DIR/logs — the
# one directory the systemd unit's ReadWritePaths already covers.
dflt="$(env -u FUZZ_LOG_DIR NOTIFIED_STATE_DIR=/opt/keyorix-fuzz/state bash -c 'source "$0"; echo "$FUZZ_LOG_DIR"' "$LIB")"
check "default FUZZ_LOG_DIR is \$NOTIFIED_STATE_DIR/logs" '[[ "$dflt" == /opt/keyorix-fuzz/state/logs ]]'

# 8. FUZZ_POST_FAILURES=0 keeps logs on the box only.
FUZZ_POST_FAILURES=0
runlog_start FuzzLocalOnly ./internal/z 15m
fake_run 1 >>"$RUNLOG"
runlog_finish 1
check "FUZZ_POST_FAILURES=0 keeps the log but does not queue it" '[[ -f "$RUNLOG_FINAL" ]] && ! ls "$FUZZ_LOG_DIR/.pending-post" | grep -q FuzzLocalOnly'

echo
if [[ "$fails" -ne 0 ]]; then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all checks passed"
