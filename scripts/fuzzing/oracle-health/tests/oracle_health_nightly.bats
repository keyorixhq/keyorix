#!/usr/bin/env bats
# Tests for nightly/oracle-health-nightly.sh with a stubbed oracle-health.sh, curl,
# timeout and host gate, over a real throwaway origin + clone. No go test runs and
# nothing leaves the machine.
# Run: bats scripts/fuzzing/oracle-health/tests/oracle_health_nightly.bats

setup() {
	HERE="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	# OHN_TEST_SCRIPT points the suite at a mutated copy (red demonstrations).
	NIGHTLY="${OHN_TEST_SCRIPT:-$HERE/nightly/oracle-health-nightly.sh}"
	S="$BATS_TEST_TMPDIR"
	mkdir -p "$S/bin" "$S/shm" "$S/locks" "$S/state"

	# --- stubs ---------------------------------------------------------------
	# timeout [-k N] SECS cmd...: no clock, just run the command (STUB_TIMEOUT_RC overrides).
	cat >"$S/bin/timeout" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "-k" ] && shift 2
shift
case "$*" in *oracle*) [ -z "${STUB_TIMEOUT_RC:-}" ] || exit "$STUB_TIMEOUT_RC" ;; esac
exec "$@"
EOF
	# curl: record the stdin config, the argv and the body file; exit CURL_RC (default 0).
	cat >"$S/bin/curl" <<'EOF'
#!/usr/bin/env bash
n=$(ls "$STUB_DIR"/curl.*.cfg 2>/dev/null | wc -l | tr -d ' ')
n=$((n + 1))
cat >"$STUB_DIR/curl.$n.cfg"
printf '%s\n' "$@" >"$STUB_DIR/curl.$n.argv"
while [ $# -gt 0 ]; do
	[ "$1" = "--data-binary" ] && { cp "${2#@}" "$STUB_DIR/curl.$n.body"; break; }
	shift
done
exit "${CURL_RC:-0}"
EOF
	# oracle-health.sh: write STUB_TSV to the --tsv path, record args and env, exit STUB_RC.
	cat >"$S/oracle.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >"$STUB_DIR/oracle.args"
echo "GOMAXPROCS=$GOMAXPROCS TMPDIR=$TMPDIR GOTMPDIR=$GOTMPDIR" >"$STUB_DIR/oracle.env"
echo "$(date +%s)" >>"$STUB_DIR/oracle.runs"
while [ $# -gt 0 ]; do
	[ "$1" = "--tsv" ] && tsv=$2
	shift
done
[ -z "${STUB_TSV:-}" ] || [ ! -f "$STUB_TSV" ] || cp "$STUB_TSV" "$tsv"
echo "oracle-health: fake output ${FAKE_OUT:-}"
exit "${STUB_RC:-0}"
EOF
	# gate: go unless $S/gate.refuse exists (its content is the reason).
	cat >"$S/gate.sh" <<'EOF'
#!/usr/bin/env bash
[ ! -e "$STUB_DIR/gate.refuse" ] || { cat "$STUB_DIR/gate.refuse"; exit 1; }
exit 0
EOF
	chmod +x "$S/bin/timeout" "$S/bin/curl" "$S/oracle.sh" "$S/gate.sh"

	# --- a real origin and a dedicated clone ---------------------------------
	git init -q --bare -b main "$S/origin.git"
	git init -q -b main "$S/seed"
	echo one >"$S/seed/f"
	git -C "$S/seed" add f
	git -C "$S/seed" -c user.name=t -c user.email=t@example.invalid commit -q -m one
	git -C "$S/seed" push -q "$S/origin.git" main
	git clone -q "$S/origin.git" "$S/clone"

	export STUB_DIR="$S" STUB_TSV="$S/result.tsv"
	export PATH="$S/bin:$PATH"
	export OHN_CLONE="$S/clone" OHN_STATE_DIR="$S/state" OHN_LOG_DIR="$S/logs"
	export OHN_ORACLE="$S/oracle.sh" OHN_GATE_CMD="$S/gate.sh" OHN_TMPFS="$S/shm"
	export OHN_HOST_LOCK="$S/locks/PVE-BENCH-LOCK" OHN_PG_BIN="$S/nonexistent"
	export OHN_NTFY_URL="https://ntfy.example.invalid/topic-name" OHN_TODAY=2026-11-27
	unset OHN_NTFY_TOKEN KEYORIX_TEST_PG_DSN STUB_RC STUB_TIMEOUT_RC CURL_RC FAKE_OUT
	healthy_tsv
}

# tsv <entry:verdict[:why]>...: write the result table the runner would.
tsv() {
	{
		printf 'entry\tcontrol\tplanted\tsecs\tverdict\ttree\n'
		local r id v why
		for r in "$@"; do
			id=${r%%:*}
			v=${r#*:}
			why=""
			case $v in *:*) why=${v#*:}; v=${v%%:*} ;; esac
			printf '%s\tPASS\tPASS\t3\t%s%s\tabc123def456\n' "$id" "$v" "${why:+  ($why)}"
		done
	} >"$STUB_TSV"
}

healthy_tsv() { tsv alpha:DETECTED beta:DETECTED gamma:KNOWN-BLIND:open\ finding\ \#4750; }

# absent <grep args>: fail the test when grep FINDS the pattern. (A bare `! grep`
# never trips bats' errexit, so it would be a silent no-op.)
absent() { if grep -q "$@" 2>/dev/null; then return 1; fi; }

curl_calls() { ls "$S"/curl.*.cfg 2>/dev/null | wc -l | tr -d ' '; }
oracle_runs() { wc -l <"$S/oracle.runs" 2>/dev/null | tr -d ' ' || echo 0; }

# ---- gate: lock, skips, staleness ---------------------------------------------

@test "lock present: silent skip, exit 0, reason logged, no alert, oracle not run" {
	touch "$S/locks/PVE-BENCH-LOCK"
	run "$NIGHTLY"
	[ "$status" -eq 0 ]
	[ "$(curl_calls)" = 0 ]
	[ ! -e "$S/oracle.args" ]
	grep -q 'SKIPPED night 1 in a row: host lock .*PVE-BENCH-LOCK present' "$S/logs/nightly.log"
	[ "$(cat "$S/state/consecutive-skips")" = 1 ]
}

@test "three consecutive skips alert once the third night; the first two stay silent" {
	touch "$S/locks/PVE-BENCH-LOCK"
	run "$NIGHTLY"; [ "$status" -eq 0 ]
	run "$NIGHTLY"; [ "$status" -eq 0 ]
	[ "$(curl_calls)" = 0 ]
	run "$NIGHTLY"; [ "$status" -eq 0 ]
	[ "$(curl_calls)" = 1 ]
	grep -q 'STALE=SKIPPED-3-NIGHTS' "$S/curl.1.cfg"
	grep -q 'host lock' "$S/curl.1.body"
}

@test "a run in between resets the skip counter" {
	touch "$S/locks/PVE-BENCH-LOCK"
	run "$NIGHTLY"; run "$NIGHTLY"
	rm "$S/locks/PVE-BENCH-LOCK"
	run "$NIGHTLY"; [ "$status" -eq 0 ]
	[ "$(cat "$S/state/consecutive-skips")" = 0 ]
	touch "$S/locks/PVE-BENCH-LOCK"
	run "$NIGHTLY"; run "$NIGHTLY"
	[ "$(curl_calls)" = 0 ]
}

@test "a gate refusal (host busy) is a skip with its reason" {
	echo "load5 7.1 >= 6" >"$S/gate.refuse"
	run "$NIGHTLY"
	[ "$status" -eq 0 ]
	[ "$(curl_calls)" = 0 ]
	grep -q 'gate command refused: load5 7.1 >= 6' "$S/logs/nightly.log"
}

@test "a lock directory the user cannot search refuses (fail closed) instead of assuming no lock" {
	[ "$(id -u)" -ne 0 ] || skip "root can search everything"
	chmod 000 "$S/locks"
	run "$NIGHTLY"
	chmod 755 "$S/locks"
	[ "$status" -eq 0 ]
	[ ! -e "$S/oracle.args" ]
	grep -q 'no search permission' "$S/logs/nightly.log"
}

@test "built-in gate: temperature, load, memory and shm thresholds, and unreadable sensors" {
	unset OHN_GATE_CMD
	export OHN_TEMP_CMD="echo 70.5"
	printf '0.5 1.0 1.0 1/100 1\n' >"$S/loadavg"
	printf 'MemTotal: 33554432 kB\nMemAvailable: 20971520 kB\n' >"$S/meminfo"
	export OHN_LOADAVG_FILE="$S/loadavg" OHN_MEMINFO_FILE="$S/meminfo"
	run "$NIGHTLY" --gate-only
	[ "$status" -eq 0 ]
	[ "$output" = "gate: go" ]

	OHN_TEMP_CMD="echo 86" run "$NIGHTLY" --gate-only
	[ "$status" -eq 1 ]
	[[ "$output" == *"temp_avg 86C >= 86C"* ]]

	OHN_TEMP_CMD="echo 85.9" run "$NIGHTLY" --gate-only
	[ "$status" -eq 0 ]

	OHN_TEMP_CMD="false" run "$NIGHTLY" --gate-only
	[ "$status" -eq 1 ]
	[[ "$output" == *"temperature unreadable"* ]]

	printf '0.5 6.00 1.0 1/100 1\n' >"$S/loadavg"
	run "$NIGHTLY" --gate-only
	[ "$status" -eq 1 ]
	[[ "$output" == *"load5 6.00 >= 6"* ]]

	printf '0.5 1.0 1.0 1/100 1\n' >"$S/loadavg"
	printf 'MemAvailable: 11534336 kB\n' >"$S/meminfo"
	run "$NIGHTLY" --gate-only
	[ "$status" -eq 1 ]
	[[ "$output" == *"mem available 11G < 12G"* ]]

	printf 'MemAvailable: 20971520 kB\n' >"$S/meminfo"
	OHN_MIN_SHM_FREE_MB=999999999 run "$NIGHTLY" --gate-only
	[ "$status" -eq 1 ]
	[[ "$output" == *"free"*"<"* ]]
}

@test "--test-alert sends one TEST message and runs nothing; a failed send exits 1" {
	run "$NIGHTLY" --test-alert
	[ "$status" -eq 0 ]
	[ "$(curl_calls)" = 1 ]
	grep -q 'Title: oracle-health: TEST-.*=TEST' "$S/curl.1.cfg"
	[ ! -e "$S/oracle.args" ]
	CURL_RC=7 run "$NIGHTLY" --test-alert
	[ "$status" -eq 1 ]
}

# ---- healthy / unhealthy runs ----------------------------------------------------

@test "healthy run: no alert, exit 0, summary and full log written, runner flags and env as specified" {
	run "$NIGHTLY"
	[ "$status" -eq 0 ]
	[ "$(curl_calls)" = 0 ]
	[ "$(oracle_runs)" = 1 ]
	grep -q -- '--heavy --strict' "$S/oracle.args"
	grep -q "GOMAXPROCS=2 TMPDIR=$S/shm/" "$S/oracle.env"
	f=$(ls "$S"/logs/oracle-health-*.summary)
	[ "$(grep -c . "$f")" = 4 ]
	grep -q $'^alpha\tDETECTED' "$f"
	grep -q $'^gamma\tKNOWN-BLIND\topen finding #4750' "$f"
	grep -q 'fake output' "$(ls "$S"/logs/oracle-health-*.log)"
	# the scratch dir on tmpfs is gone afterwards
	[ -z "$(ls -A "$S/shm")" ]
}

@test "a MISSED entry sends exactly one alert whose title names it" {
	tsv alpha:DETECTED beta:MISSED gamma:KNOWN-BLIND
	STUB_RC=1 run "$NIGHTLY"
	[ "$status" -eq 1 ]
	[ "$(curl_calls)" = 1 ]
	grep -q 'Title: oracle-health: beta=MISSED' "$S/curl.1.cfg"
	absent 'alpha' "$S/curl.1.cfg"
	grep -q '^beta MISSED' "$S/curl.1.body"
}

@test "several bad entries still make one message, naming all of them; the body is capped at 1 KB" {
	long=$(printf 'x%.0s' $(seq 1 400))
	tsv a1:MISSED:"$long" a2:CONTROL-RED:"$long" a3:BLIND-FIXED:"$long" a4:SKIP:"$long" a5:PLANT-STALE a6:WRONG-MARKER
	STUB_RC=1 run "$NIGHTLY"
	[ "$(curl_calls)" = 1 ]
	for e in a1=MISSED a2=CONTROL-RED a3=BLIND-FIXED a4=SKIP a5=PLANT-STALE a6=WRONG-MARKER; do
		grep -q "$e" "$S/curl.1.cfg"
	done
	[ "$(wc -c <"$S/curl.1.body" | tr -d ' ')" -le 1024 ]
}

@test "the same entry twice in one day alerts once; another entry, or the next day, alerts again" {
	tsv alpha:MISSED
	STUB_RC=1 run "$NIGHTLY"
	STUB_RC=1 run "$NIGHTLY"
	[ "$status" -eq 1 ]
	[ "$(curl_calls)" = 1 ]

	tsv alpha:MISSED beta:CONTROL-RED
	STUB_RC=1 run "$NIGHTLY"
	[ "$(curl_calls)" = 2 ]
	grep -q 'beta=CONTROL-RED' "$S/curl.2.cfg"
	absent 'alpha' "$S/curl.2.cfg"

	OHN_TODAY=2026-11-28 STUB_RC=1 run "$NIGHTLY"
	[ "$(curl_calls)" = 3 ]
	grep -q 'alpha=MISSED' "$S/curl.3.cfg"
}

@test "KNOWN-BLIND alone is accepted; a SKIP under --strict is not" {
	tsv alpha:DETECTED gamma:KNOWN-BLIND
	run "$NIGHTLY"
	[ "$status" -eq 0 ]
	[ "$(curl_calls)" = 0 ]
	tsv alpha:DETECTED canary-echo-pg:SKIP:needs\ KEYORIX_TEST_PG_DSN
	STUB_RC=3 run "$NIGHTLY"
	[ "$(curl_calls)" = 1 ]
	grep -q 'canary-echo-pg=SKIP' "$S/curl.1.cfg"
}

@test "the runner failing while every row reads healthy is itself alerted, not trusted" {
	STUB_RC=1 run "$NIGHTLY"
	[ "$status" -eq 1 ]
	[ "$(curl_calls)" = 1 ]
	grep -q 'run=EXIT-1' "$S/curl.1.cfg"
}

@test "no result table: a timeout and a crash are alerted under the run key" {
	rm -f "$STUB_TSV"
	STUB_TIMEOUT_RC=124 run "$NIGHTLY"
	[ "$status" -eq 1 ]
	grep -q 'run=TIMEOUT' "$S/curl.1.cfg"
	OHN_TODAY=2026-11-28 STUB_RC=2 run "$NIGHTLY"
	grep -q 'run=NO-RESULT' "$S/curl.2.cfg"
}

@test "a failed curl is not recorded as sent: the next run retries" {
	tsv alpha:MISSED
	CURL_RC=7 STUB_RC=1 run "$NIGHTLY"
	[ "$status" -eq 1 ]
	grep -q 'ntfy send FAILED' "$S/logs/nightly.log"
	STUB_RC=1 run "$NIGHTLY"
	[ "$(curl_calls)" = 2 ]
	STUB_RC=1 run "$NIGHTLY"
	[ "$(curl_calls)" = 2 ]
}

# ---- clone handling --------------------------------------------------------------

@test "the clone is fast-forwarded to origin/main before the run" {
	echo two >"$S/seed/f"
	git -C "$S/seed" -c user.name=t -c user.email=t@example.invalid commit -q -am two
	git -C "$S/seed" push -q "$S/origin.git" main
	run "$NIGHTLY"
	[ "$status" -eq 0 ]
	[ "$(git -C "$S/clone" rev-parse HEAD)" = "$(git -C "$S/seed" rev-parse HEAD)" ]
}

@test "a dirty clone is refused and alerted, and the suite does not run" {
	echo scribble >>"$S/clone/f"
	run "$NIGHTLY"
	[ "$status" -eq 1 ]
	[ ! -e "$S/oracle.args" ]
	grep -q 'CLONE=CLONE-REFUSED' "$S/curl.1.cfg"
	grep -q 'dirty' "$S/curl.1.body"
}

@test "a clone that cannot fast-forward is refused" {
	git -C "$S/clone" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m local
	echo two >"$S/seed/f"
	git -C "$S/seed" -c user.name=t -c user.email=t@example.invalid commit -q -am two
	git -C "$S/seed" push -q "$S/origin.git" main
	run "$NIGHTLY"
	[ "$status" -eq 1 ]
	[ ! -e "$S/oracle.args" ]
	grep -q 'cannot fast-forward' "$S/curl.1.body"
}

# ---- secrets ---------------------------------------------------------------------

@test "the DSN never reaches the log, the summary, the message or curl's argv" {
	export KEYORIX_TEST_PG_DSN='postgres://su:hunter2hunter2@db.internal:5432/postgres'
	export OHN_NTFY_TOKEN=tk_sEcReT123
	export FAKE_OUT="dsn=$KEYORIX_TEST_PG_DSN password=hunter2hunter2 Bearer tk_sEcReT123"
	tsv alpha:MISSED:"failed on $KEYORIX_TEST_PG_DSN"
	STUB_RC=1 run "$NIGHTLY"
	[ "$(curl_calls)" = 1 ]
	absent -r 'hunter2' "$S/logs" "$S/curl.1.body" "$S/curl.1.cfg" "$S/curl.1.argv"
	absent 'tk_sEcReT123' "$S/curl.1.argv" "$S/curl.1.body" "$S"/logs/*
	grep -q 'Authorization: Bearer tk_sEcReT123' "$S/curl.1.cfg"
	absent 'ntfy.example.invalid' "$S/curl.1.argv"
}
