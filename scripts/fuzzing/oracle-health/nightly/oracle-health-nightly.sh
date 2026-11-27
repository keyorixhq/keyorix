#!/usr/bin/env bash
# oracle-health-nightly.sh -- run the oracle-health suite (--heavy --strict) on a
# dedicated clone of origin/main, keep the output, and tell a human when a harness
# has gone blind. Meant for a systemd timer on the shared fuzz host (pve01); no
# GitHub workflow is involved. Runbook: docs/fuzzing/oracle-health-nightly.md.
#
# One run:
#   1. gate    skip quietly (exit 0, reason logged, no alert) when PVE-BENCH-LOCK
#              exists or the host is hot/busy (temp_avg>=86C, load5>=6, mem avail
#              <12G, /dev/shm free <8G). A night skipped OHN_SKIP_ALERT_AFTER (3)
#              times in a row raises one "stale" alert, because a suite that never
#              runs is as blind as a harness that never fails.
#   2. clone   fast-forward the dedicated clone to origin/main; a dirty tree, a
#              branch other than main, a failed fetch or a non-fast-forward is a
#              refusal (alerted), never a run on a stale tree.
#   3. run     nice 10, GOMAXPROCS=2, hard timeout, scratch trees on tmpfs:
#              oracle-health.sh --heavy --strict --tsv <file>
#   4. record  full (redacted) output and a one-line-per-entry summary under
#              $OHN_LOG_DIR, dated.
#   5. alert   any verdict other than DETECTED / KNOWN-BLIND (an open finding the
#              registry already accepts) -> ONE ntfy message per run, title names
#              the entries, body <= 1 KB, at most one alert per entry per UTC day.
#              A fully healthy run sends nothing.
#
# What this does NOT verify: that every harness HAS an entry (a new harness with no
# entry is invisible here), that an entry's plant is a realistic defect, or that
# the registry is complete. See the doc.
#
# Usage: oracle-health-nightly.sh [--gate-only | --test-alert] [-h]
#   --gate-only  evaluate the gate, print the decision, change nothing (exit 0 go,
#                1 refuse). Use it once by hand after install: a sensor that cannot
#                be read refuses, and you want to learn that now, not after 3 nights.
#   --test-alert send one TEST message through the real ntfy path (exit 0 sent, 1 not)
#                and nothing else; no gate, no run, no counters.
# Exit: 0 healthy, skipped, or another run in progress; 1 unhealthy (verdicts,
#       timeout, refused clone); 2 misconfigured (missing tool or directory).
#
# Configuration: environment (systemd EnvironmentFile, see oracle-health-nightly.env.example).
# Test hooks (used by tests/oracle_health_nightly.bats): OHN_ORACLE, OHN_GATE_CMD,
# OHN_TEMP_CMD, OHN_LOADAVG_FILE, OHN_MEMINFO_FILE, OHN_TODAY.
set -u

: "${OHN_CLONE:=/opt/oracle-health-nightly/keyorix}"
: "${OHN_STATE_DIR:=/var/lib/oracle-health-nightly}"
: "${OHN_LOG_DIR:=$OHN_STATE_DIR/logs}"
: "${OHN_LOG_KEEP_DAYS:=30}"
: "${OHN_REMOTE:=origin}"
: "${OHN_BRANCH:=main}"
: "${OHN_ORACLE:=$OHN_CLONE/scripts/fuzzing/oracle-health/oracle-health.sh}"
: "${OHN_TIMEOUT_SECS:=10800}"
: "${OHN_FETCH_TIMEOUT_SECS:=300}"
: "${OHN_TMPFS:=/dev/shm}"
: "${OHN_PG_BIN:=/usr/lib/postgresql/17/bin}"
: "${OHN_HOST_LOCK:=/root/PVE-BENCH-LOCK}"
: "${OHN_GATE_CMD:=}"
: "${OHN_TEMP_CMD:=}"
: "${OHN_MAX_TEMP_C:=86}"
: "${OHN_MAX_LOAD5:=6}"
: "${OHN_MIN_MEM_AVAIL_GB:=12}"
: "${OHN_MIN_SHM_FREE_MB:=8192}"
: "${OHN_LOADAVG_FILE:=/proc/loadavg}"
: "${OHN_MEMINFO_FILE:=/proc/meminfo}"
: "${OHN_SKIP_ALERT_AFTER:=3}"
: "${OHN_NTFY_URL:=https://ntfy.sh/andrey_fuzz_allert}"
: "${OHN_NTFY_TOKEN:=}"
: "${OHN_TODAY:=$(date -u +%F)}"

SKIP_FILE="$OHN_STATE_DIR/consecutive-skips"
ALERTED_FILE="$OHN_STATE_DIR/alerted.tsv"
RUNLOCK="$OHN_STATE_DIR/run.lock"
NIGHTLY_LOG="$OHN_LOG_DIR/nightly.log"
GATE_REASON=""
TMP=""

log() {
	local line
	line="$(date -u +%Y-%m-%dT%H:%M:%SZ) oracle-health-nightly: $*"
	echo "$line" >&2
	[ -d "$OHN_LOG_DIR" ] && echo "$line" >>"$NIGHTLY_LOG"
	return 0
}

# redact: keep DSNs, passwords and tokens out of logs and messages.
redact() {
	local dsn=${KEYORIX_TEST_PG_DSN:-}
	sed -E -e 's#postgres(ql)?://[^[:space:]"'\'']+#postgres://REDACTED#g' \
		-e 's#([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]=)[^[:space:]]+#\1REDACTED#g' \
		-e 's#([Bb]earer )[^[:space:]]+#\1REDACTED#g' |
		OHN_SECRET1=$dsn OHN_SECRET2=$OHN_NTFY_TOKEN awk '
		{ for (k = 1; k <= 2; k++) { s = ENVIRON["OHN_SECRET" k]
			while (length(s) > 7 && (i = index($0, s)) > 0) $0 = substr($0, 1, i - 1) "REDACTED" substr($0, i + length(s)) }
		  print }'
}

# --- gate --------------------------------------------------------------------

# gate_refuse <reason>: record the reason and refuse.
gate_refuse() { GATE_REASON=$1; return 1; }

# gate_check: return 0 to go. On refusal set GATE_REASON and return 1. Fail closed:
# a lock directory the service user cannot search, or a sensor that cannot be
# read, refuses rather than guessing "all clear".
gate_check() {
	local lock dir out
	for lock in $OHN_HOST_LOCK; do
		dir=$(dirname "$lock")
		[ -x "$dir" ] || { gate_refuse "cannot look for $lock: no search permission on $dir"; return 1; }
		[ ! -e "$lock" ] || { gate_refuse "host lock $lock present"; return 1; }
	done
	if [ -n "$OHN_GATE_CMD" ]; then
		out=$($OHN_GATE_CMD 2>&1) && return 0
		gate_refuse "gate command refused: $(printf '%s' "$out" | head -n 1 | cut -c1-160)"
		return 1
	fi
	gate_builtin
}

gate_builtin() {
	local temp load5 mem_kb shm_kb
	if [ -n "$OHN_TEMP_CMD" ]; then
		temp=$($OHN_TEMP_CMD 2>/dev/null | head -n 1)
	else
		temp=$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null |
			awk '$1 > 0 { s += $1; n++ } END { if (n) printf "%.1f", s / n / 1000 }')
	fi
	case $temp in '' | *[!0-9.]*) gate_refuse "temperature unreadable (set OHN_TEMP_CMD)"; return 1 ;; esac
	awk -v v="$temp" -v m="$OHN_MAX_TEMP_C" 'BEGIN { exit !(v >= m) }' &&
		{ gate_refuse "temp_avg ${temp}C >= ${OHN_MAX_TEMP_C}C"; return 1; }

	load5=$(awk '{ print $2 }' "$OHN_LOADAVG_FILE" 2>/dev/null)
	case $load5 in '' | *[!0-9.]*) gate_refuse "load average unreadable ($OHN_LOADAVG_FILE)"; return 1 ;; esac
	awk -v v="$load5" -v m="$OHN_MAX_LOAD5" 'BEGIN { exit !(v >= m) }' &&
		{ gate_refuse "load5 $load5 >= $OHN_MAX_LOAD5"; return 1; }

	mem_kb=$(awk '/^MemAvailable:/ { print $2 }' "$OHN_MEMINFO_FILE" 2>/dev/null)
	case $mem_kb in '' | *[!0-9]*) gate_refuse "MemAvailable unreadable ($OHN_MEMINFO_FILE)"; return 1 ;; esac
	awk -v v="$mem_kb" -v m="$OHN_MIN_MEM_AVAIL_GB" 'BEGIN { exit !(v < m * 1048576) }' &&
		{ gate_refuse "mem available $((mem_kb / 1048576))G < ${OHN_MIN_MEM_AVAIL_GB}G"; return 1; }

	shm_kb=$(df -Pk "$OHN_TMPFS" 2>/dev/null | awk 'NR == 2 { print $4 }')
	case $shm_kb in '' | *[!0-9]*) gate_refuse "cannot read free space of $OHN_TMPFS"; return 1 ;; esac
	[ "$shm_kb" -ge $((OHN_MIN_SHM_FREE_MB * 1024)) ] ||
		{ gate_refuse "$OHN_TMPFS free $((shm_kb / 1024))M < ${OHN_MIN_SHM_FREE_MB}M"; return 1; }
	return 0
}

# --- alerts ------------------------------------------------------------------

# alert <items-file>: items are key<TAB>VERDICT<TAB>detail. Drops keys already
# alerted on today, sends one message for the rest, records the keys only when
# curl succeeded (a failed send is retried by the next run).
alert() {
	local items=$1 fresh="$TMP/alert.fresh" body="$TMP/alert.body" title n k v d
	: >"$fresh"
	while IFS=$'\t' read -r k v d; do
		[ -n "$k" ] || continue
		if grep -qxF "$k	$OHN_TODAY" "$ALERTED_FILE" 2>/dev/null; then
			log "alert for $k already sent today, not repeating"
			continue
		fi
		printf '%s\t%s\t%s\n' "$k" "$v" "$d" >>"$fresh"
	done <"$items"
	n=$(wc -l <"$fresh" | tr -d ' ')
	[ "$n" -gt 0 ] || { log "no new alerts after the per-day limit"; return 0; }

	title="oracle-health: $(awk -F'\t' '{ printf "%s%s=%s", (NR > 1 ? ", " : ""), $1, $2 }' "$fresh")"
	title=$(printf '%s' "$title" | tr -cd '[:print:]' | tr -d '"' | tr -d "\\\\" | cut -c1-180)
	{
		awk -F'\t' '{ printf "%s %s%s\n", $1, $2, ($3 != "" ? " - " $3 : "") }' "$fresh"
		echo "host=$(hostname -s 2>/dev/null) tree=${TREE:-unknown} log=${FULL_LOG:-$NIGHTLY_LOG}"
	} | redact | head -c 1024 >"$body"

	if [ -z "$OHN_NTFY_URL" ]; then
		log "OHN_NTFY_URL empty: alert not sent: $title"
		return 1
	fi
	# URL and token go through `curl -K -` (stdin), never argv, so they stay out of ps.
	if ! {
		printf 'url = "%s"\n' "$OHN_NTFY_URL"
		printf 'header = "Title: %s"\n' "$title"
		printf 'header = "Priority: high"\nheader = "Tags: rotating_light"\n'
		case $OHN_NTFY_TOKEN in
		'') ;;
		*[!A-Za-z0-9_.-]*) log "OHN_NTFY_TOKEN has unexpected characters, sending without it" ;;
		*) printf 'header = "Authorization: Bearer %s"\n' "$OHN_NTFY_TOKEN" ;;
		esac
	} | curl -sS -f --max-time 30 -K - --data-binary "@$body" >/dev/null 2>"$TMP/curl.err"; then
		log "ntfy send FAILED ($(redact <"$TMP/curl.err" | head -n 1 | cut -c1-120)); will retry next run"
		return 1
	fi
	while IFS=$'\t' read -r k _; do
		printf '%s\t%s\n' "$k" "$OHN_TODAY" >>"$ALERTED_FILE"
	done <"$fresh"
	log "alert sent: $title"
	return 0
}

# alert_one <key> <VERDICT> <detail>
alert_one() {
	printf '%s\t%s\t%s\n' "$1" "$2" "$3" >"$TMP/alert.one"
	alert "$TMP/alert.one"
}

# --- helpers -----------------------------------------------------------------

read_int() {
	local v=0
	[ -r "$1" ] && v=$(head -n 1 "$1" 2>/dev/null)
	case $v in '' | *[!0-9]*) v=0 ;; esac
	echo "$v"
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	[ -z "$TMP" ] || rm -rf "$TMP" 2>/dev/null
	rm -rf "$RUNLOCK" 2>/dev/null
}

find_timeout() {
	command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null
}

# prepare_clone: fast-forward only. Prints the reason on refusal.
prepare_clone() {
	local timeout_bin=$1 dirty cur
	[ -e "$OHN_CLONE/.git" ] || { echo "no git clone at $OHN_CLONE"; return 1; }
	dirty=$(git -C "$OHN_CLONE" status --porcelain 2>&1 | head -n 5) || true
	[ -z "$dirty" ] || { echo "clone is dirty, refusing: $(echo "$dirty" | head -n 3 | tr '\n' ';' | cut -c1-200)"; return 1; }
	cur=$(git -C "$OHN_CLONE" rev-parse --abbrev-ref HEAD 2>/dev/null)
	[ "$cur" = "$OHN_BRANCH" ] || { echo "clone is on '$cur', not $OHN_BRANCH"; return 1; }
	git -C "$OHN_CLONE" worktree prune >/dev/null 2>&1
	GIT_TERMINAL_PROMPT=0 "$timeout_bin" "$OHN_FETCH_TIMEOUT_SECS" git -C "$OHN_CLONE" fetch --quiet "$OHN_REMOTE" "$OHN_BRANCH" >"$TMP/git.out" 2>&1 ||
		{ echo "git fetch failed: $(redact <"$TMP/git.out" | head -n 1 | cut -c1-160)"; return 1; }
	git -C "$OHN_CLONE" merge --ff-only --quiet "$OHN_REMOTE/$OHN_BRANCH" >"$TMP/git.out" 2>&1 ||
		{ echo "cannot fast-forward to $OHN_REMOTE/$OHN_BRANCH: $(head -n 1 "$TMP/git.out" | cut -c1-160)"; return 1; }
	return 0
}

# --- main --------------------------------------------------------------------

gate_only=0 test_alert=0
while [ $# -gt 0 ]; do
	case $1 in
	--gate-only) gate_only=1 ;;
	--test-alert) test_alert=1 ;;
	-h | --help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
	*) echo "oracle-health-nightly: unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

if [ $gate_only = 1 ]; then
	if gate_check; then echo "gate: go"; exit 0; fi
	echo "gate: refuse: $GATE_REASON"
	exit 1
fi

for tool in git curl awk sed nice; do
	command -v "$tool" >/dev/null 2>&1 || { echo "oracle-health-nightly: $tool not found" >&2; exit 2; }
done
TIMEOUT_BIN=$(find_timeout) || { echo "oracle-health-nightly: neither timeout nor gtimeout found" >&2; exit 2; }
mkdir -p "$OHN_STATE_DIR" "$OHN_LOG_DIR" || { echo "oracle-health-nightly: cannot create $OHN_STATE_DIR / $OHN_LOG_DIR" >&2; exit 2; }

# One run at a time (timer + a manual run, or a run that overran into the next night).
if ! mkdir "$RUNLOCK" 2>/dev/null; then
	holder=$(cat "$RUNLOCK/pid" 2>/dev/null)
	if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
		log "another run is in progress (pid $holder), exiting"
		exit 0
	fi
	log "removing stale run lock (pid ${holder:-?} is gone)"
	rm -rf "$RUNLOCK"
	mkdir "$RUNLOCK" || exit 2
fi
echo $$ >"$RUNLOCK/pid"
TMP=$(mktemp -d "$OHN_STATE_DIR/tmp.XXXXXX") || exit 2
trap cleanup EXIT

if [ $test_alert = 1 ]; then
	alert_one "TEST-$$-$(date -u +%Y%m%dT%H%M%SZ)" "TEST" "alert path check from $(hostname -s 2>/dev/null)"
	exit $?
fi

# 1. gate
if ! gate_check; then
	skips=$(( $(read_int "$SKIP_FILE") + 1 ))
	echo "$skips" >"$SKIP_FILE"
	log "SKIPPED night $skips in a row: $GATE_REASON"
	if [ "$skips" -ge "$OHN_SKIP_ALERT_AFTER" ]; then
		alert_one "STALE" "SKIPPED-${skips}-NIGHTS" "last reason: $GATE_REASON"
	fi
	exit 0
fi
echo 0 >"$SKIP_FILE"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FULL_LOG="$OHN_LOG_DIR/oracle-health-$STAMP.log"
SUMMARY="$OHN_LOG_DIR/oracle-health-$STAMP.summary"
TREE=""

# 2. clone
if ! reason=$(prepare_clone "$TIMEOUT_BIN"); then
	log "REFUSED: $reason"
	alert_one "CLONE" "CLONE-REFUSED" "$reason"
	exit 1
fi
TREE=$(git -C "$OHN_CLONE" rev-parse --short=12 HEAD 2>/dev/null)

# 3. run
scratch=$(mktemp -d "$OHN_TMPFS/oracle-health-nightly.XXXXXX") || { log "cannot create a temp dir under $OHN_TMPFS"; alert_one "TMPFS" "NO-TMPFS" "cannot create a temp dir under $OHN_TMPFS"; exit 1; }
mkdir -p "$scratch/work" "$scratch/tmp" "$scratch/gotmp"
trap 'rm -rf "$scratch" 2>/dev/null; cleanup' EXIT
[ ! -d "$OHN_PG_BIN" ] || PATH="$OHN_PG_BIN:$PATH"
export PATH

log "start tree=$TREE log=$FULL_LOG"
t0=$(date +%s)
GOMAXPROCS=2 TMPDIR="$scratch/tmp" GOTMPDIR="$scratch/gotmp" \
	nice -n 10 "$TIMEOUT_BIN" -k 120 "$OHN_TIMEOUT_SECS" \
	bash "$OHN_ORACLE" --heavy --strict --workdir "$scratch/work" --tsv "$scratch/result.tsv" >"$scratch/raw.log" 2>&1
rc=$?
secs=$(($(date +%s) - t0))
redact <"$scratch/raw.log" >"$FULL_LOG"

# 4. record: one line per entry, plus a header line.
: >"$TMP/items"
: >"$SUMMARY"
printf '# tree=%s rc=%s secs=%s date=%s\n' "$TREE" "$rc" "$secs" "$STAMP" >>"$SUMMARY"
rows=0
if [ -s "$scratch/result.tsv" ]; then
	awk -F'\t' 'NR > 1 && $1 != "" {
		v = $5; why = ""
		if (match(v, /  \(.*\)$/)) { why = substr(v, RSTART + 3, RLENGTH - 4); v = substr(v, 1, RSTART - 1) }
		sub(/ .*/, "", v)
		printf "%s\t%s\t%s\n", $1, v, why }' "$scratch/result.tsv" | redact >"$TMP/rows"
	rows=$(wc -l <"$TMP/rows" | tr -d ' ')
	cat "$TMP/rows" >>"$SUMMARY"
	awk -F'\t' '$2 != "DETECTED" && $2 != "KNOWN-BLIND"' "$TMP/rows" >"$TMP/items"
fi
if [ "$rows" -eq 0 ]; then
	case $rc in
	124 | 137) v=TIMEOUT; d="no result after ${OHN_TIMEOUT_SECS}s" ;;
	*) v="NO-RESULT"; d="oracle-health.sh exited $rc without a result table" ;;
	esac
	printf 'run\t%s\t%s\n' "$v" "$d" >>"$TMP/items"
	printf 'run\t%s\t%s\n' "$v" "$d" >>"$SUMMARY"
elif [ "$rc" -ne 0 ] && [ ! -s "$TMP/items" ]; then
	# every row healthy but the runner says otherwise: do not trust the table
	printf 'run\tEXIT-%s\trunner exited %s although every entry reads healthy\n' "$rc" "$rc" >>"$TMP/items"
	printf 'run\tEXIT-%s\trunner exited %s although every entry reads healthy\n' "$rc" "$rc" >>"$SUMMARY"
fi
log "finished rc=$rc secs=$secs entries=$rows not-healthy=$(wc -l <"$TMP/items" | tr -d ' ')"

find "$OHN_LOG_DIR" -maxdepth 1 -type f -name 'oracle-health-*' -mtime +"$OHN_LOG_KEEP_DAYS" -delete 2>/dev/null

# 5. alert
if [ ! -s "$TMP/items" ]; then
	log "healthy: nothing to report"
	exit 0
fi
alert "$TMP/items"
exit 1
