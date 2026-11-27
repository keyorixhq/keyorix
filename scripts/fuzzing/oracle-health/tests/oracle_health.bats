#!/usr/bin/env bats
# Tests for the pure parts of oracle-health (lib.sh: verdict logic, marker match,
# run classification, conf parsing) and, with a stubbed `go` on PATH, one
# end-to-end run of the runner over a throwaway repository. No real go test runs.
# Run: bats scripts/fuzzing/oracle-health/tests

setup() {
	HERE="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	# shellcheck source=../lib.sh
	. "$HERE/lib.sh"
	T="$BATS_TEST_TMPDIR"
}

# ---- oh_verdict -------------------------------------------------------------

@test "verdict: control green and planted defect detected is healthy" {
	run oh_verdict PASS DETECTED ""
	[ "$output" = "DETECTED ok" ]
}

@test "verdict: a harness that stays green on its plant is MISSED and fails" {
	run oh_verdict PASS PASS ""
	[ "$output" = "MISSED bad" ]
}

@test "verdict: a red control fails whatever the plant did" {
	for planted in DETECTED PASS WRONGFAIL; do
		run oh_verdict FAIL "$planted" ""
		[ "$output" = "CONTROL-RED bad" ]
	done
	run oh_verdict ERROR DETECTED ""
	[ "$output" = "CONTROL-RED bad" ]
}

@test "verdict: a SKIP control is a SKIP, never a pass" {
	run oh_verdict SKIP PASS ""
	[ "$output" = "SKIP ok" ]
	run oh_verdict SKIP DETECTED ""
	[ "$output" = "SKIP ok" ]
}

@test "verdict: failing for another reason than the marker is WRONG-MARKER" {
	run oh_verdict PASS WRONGFAIL ""
	[ "$output" = "WRONG-MARKER bad" ]
}

@test "verdict: a patch that no longer applies or a plant that does not build fails" {
	run oh_verdict PASS NOAPPLY ""
	[ "$output" = "PLANT-STALE bad" ]
	run oh_verdict PASS ERROR ""
	[ "$output" = "PLANT-BROKEN bad" ]
}

@test "verdict: a known-blind entry stays ok while blind and fails once it sees the plant" {
	run oh_verdict PASS PASS "#4739"
	[ "$output" = "KNOWN-BLIND ok" ]
	run oh_verdict PASS DETECTED "#4739"
	[ "$output" = "BLIND-FIXED bad" ]
}

@test "verdict: a self-test entry has no separate control" {
	run oh_verdict NA DETECTED ""
	[ "$output" = "DETECTED ok" ]
	run oh_verdict NA PASS ""
	[ "$output" = "MISSED bad" ]
}

@test "exit code: bad wins, strict turns SKIPs into 3" {
	[ "$(oh_exit_code 0 0 0)" = 0 ]
	[ "$(oh_exit_code 0 0 4)" = 0 ]
	[ "$(oh_exit_code 1 0 4)" = 3 ]
	[ "$(oh_exit_code 1 1 4)" = 1 ]
	[ "$(oh_exit_code 0 2 0)" = 1 ]
}

# ---- oh_markers_match -------------------------------------------------------

@test "markers: every marker must be present, fixed-string, order free" {
	printf 'x\ninvariant 6: interrupted migration\nfoo planted_zz bar\n' >"$T/log"
	run oh_markers_match "$T/log" "planted_zz || invariant 6: interrupted migration"
	[ "$status" -eq 0 ]
	run oh_markers_match "$T/log" "planted_zz || invariant 7"
	[ "$status" -ne 0 ]
}

@test "markers: regex characters are literal and an empty marker list never matches" {
	printf 'allocated 5 bytes (limit 3)\n' >"$T/log"
	run oh_markers_match "$T/log" "allocated 5 bytes (limit 3)"
	[ "$status" -eq 0 ]
	run oh_markers_match "$T/log" "allocated .* bytes"
	[ "$status" -ne 0 ]
	run oh_markers_match "$T/log" ""
	[ "$status" -ne 0 ]
}

# ---- oh_classify_run --------------------------------------------------------

@test "classify: passing run, failing run" {
	printf '=== RUN   FuzzX\n--- PASS: FuzzX (0.01s)\n    --- PASS: FuzzX/seed#0 (0.00s)\nPASS\n' >"$T/p"
	[ "$(oh_classify_run 0 "$T/p")" = PASS ]
	printf -- '--- FAIL: FuzzX (0.01s)\nFAIL\n' >"$T/f"
	[ "$(oh_classify_run 1 "$T/f")" = FAIL ]
}

@test "classify: a harness that skips itself is SKIP, not PASS" {
	printf '=== RUN   FuzzX\n    x_test.go:9: needs SUPERUSER\n--- SKIP: FuzzX (0.2s)\nPASS\nok  \tpkg\t0.4s\n' >"$T/s"
	[ "$(oh_classify_run 0 "$T/s")" = SKIP ]
}

@test "classify: build failure, setup failure and an empty -run are ERROR, not green" {
	printf 'FAIL\tpkg [build failed]\n' >"$T/b"
	[ "$(oh_classify_run 1 "$T/b")" = ERROR ]
	printf 'FAIL\t./x [setup failed]\n' >"$T/s"
	[ "$(oh_classify_run 1 "$T/s")" = ERROR ]
	printf 'testing: warning: no tests to run\nPASS\n' >"$T/n"
	[ "$(oh_classify_run 0 "$T/n")" = ERROR ]
	printf 'ok  \tpkg\t0.1s\n' >"$T/q"
	[ "$(oh_classify_run 0 "$T/q")" = ERROR ]
}

# ---- oh_parse_conf ----------------------------------------------------------

@test "conf: parsed without shell evaluation, defaults filled" {
	cat >"$T/e.conf" <<'EOF'
# comment
PKG=./a/b
RUN=^FuzzX$/^seed#2$
MARKERS=foo $(touch /nonexistent-oh-test) || bar
EOF
	oh_parse_conf "$T/e.conf"
	[ "$OH_PKG" = "./a/b" ]
	[ "$OH_RUN" = '^FuzzX$/^seed#2$' ]
	[ "$OH_MARKERS" = 'foo $(touch /nonexistent-oh-test) || bar' ]
	[ "$OH_KIND" = plant ]
	[ "$OH_NEEDS" = none ]
	[ ! -e /nonexistent-oh-test ]
}

@test "conf: unknown key, missing marker and bad NEEDS are refused" {
	printf 'PKG=./a\nRUN=x\nMARKERS=m\nTYPO=1\n' >"$T/a.conf"
	run oh_parse_conf "$T/a.conf"
	[ "$status" -ne 0 ]
	printf 'PKG=./a\nRUN=x\n' >"$T/b.conf"
	run oh_parse_conf "$T/b.conf"
	[ "$status" -ne 0 ]
	printf 'PKG=./a\nRUN=x\nMARKERS=m\nNEEDS=mysql\n' >"$T/c.conf"
	run oh_parse_conf "$T/c.conf"
	[ "$status" -ne 0 ]
}

@test "conf: every committed entry parses and has its patch" {
	for f in "$HERE"/entries.d/*.conf; do
		oh_parse_conf "$f"
		if [ "$OH_KIND" = plant ]; then
			id=$(basename "$f" .conf)
			[ -f "$HERE/entries.d/${OH_PATCH:-$id.patch}" ]
		fi
	done
}

@test "conf: every committed dashdiag entry parses and has its patch and replay" {
	for f in "$HERE"/dashdiag.d/*.conf; do
		oh_parse_conf "$f"
		id=$(basename "$f" .conf)
		[ -f "$HERE/dashdiag.d/${OH_PATCH:-$id.patch}" ]
		[ -z "${OH_REPLAY_GEN:-}" ] || [ -f "$HERE/dashdiag.d/$OH_REPLAY_GEN" ]
	done
}

@test "conf: every committed entry with REPLAY_GEN has its generator" {
	for f in "$HERE"/entries.d/*.conf; do
		oh_parse_conf "$f"
		[ -z "${OH_REPLAY_GEN:-}" ] || [ -f "$HERE/entries.d/$OH_REPLAY_GEN" ]
	done
}

# ---- the runner end to end, with a stubbed go -------------------------------

make_repo() {
	R="$T/repo"
	mkdir -p "$R/scripts/fuzzing" "$T/bin"
	cp -R "$HERE" "$R/scripts/fuzzing/oracle-health"
	rm -f "$R"/scripts/fuzzing/oracle-health/entries.d/*
	printf 'package a\n\nvar Guard = true\n' >"$R/a.go"
	cat >"$R/scripts/fuzzing/oracle-health/entries.d/e1.conf" <<'EOF'
PKG=./.
RUN=^FuzzX$
MARKERS=ORACLE FIRED
EOF
	printf -- '--- a/a.go\n+++ b/a.go\n@@ -1,3 +1,3 @@\n package a\n \n-var Guard = true\n+var Guard = false\n' >"$R/scripts/fuzzing/oracle-health/entries.d/e1.patch"
	git -C "$R" init -q
	git -C "$R" add -A
	git -C "$R" -c user.email=t@t -c user.name=t commit -q -m base
	# stub go: green while a.go says Guard = true; with the plant, fail (or stay
	# green when STUB_BLIND=1)
	cat >"$T/bin/go" <<'EOF'
#!/bin/sh
if grep -q 'Guard = false' a.go && [ -z "$STUB_BLIND" ]; then
	echo "--- FAIL: FuzzX (0.00s)"; echo "    x_test.go:1: ORACLE FIRED"; echo FAIL; exit 1
fi
echo "=== RUN   FuzzX"; echo "--- PASS: FuzzX (0.00s)"; echo PASS; exit 0
EOF
	chmod +x "$T/bin/go"
}

@test "runner: healthy entry exits 0 and leaves no tree behind" {
	make_repo
	run env PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 0 ]
	[[ "$output" == *"e1"*"PASS"*"DETECTED"* ]]
	[ ! -d "$T/work/e1" ]
	[ -z "$(git -C "$R" status --porcelain)" ]
}

@test "runner: a blind harness exits 1 with MISSED" {
	make_repo
	run env STUB_BLIND=1 PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 1 ]
	[[ "$output" == *"MISSED"* ]]
}

@test "runner: a plant that no longer applies is PLANT-STALE" {
	make_repo
	printf -- '--- a/a.go\n+++ b/a.go\n@@ -1,3 +1,3 @@\n package a\n \n-var Gone = true\n+var Gone = false\n' >"$R/scripts/fuzzing/oracle-health/entries.d/e1.patch"
	run env PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 1 ]
	[[ "$output" == *"PLANT-STALE"* ]]
}

@test "runner: --root and --entries test another repository with its own registry" {
	make_repo
	O="$T/other"
	mkdir -p "$O" "$T/reg"
	printf 'package a\n\nvar Guard = true\n' >"$O/a.go"
	cp "$R/scripts/fuzzing/oracle-health/entries.d/e1.conf" "$T/reg/d1.conf"
	cp "$R/scripts/fuzzing/oracle-health/entries.d/e1.patch" "$T/reg/d1.patch"
	rm -f "$R"/scripts/fuzzing/oracle-health/entries.d/e1.*
	git -C "$O" init -q
	git -C "$O" add -A
	git -C "$O" -c user.email=t@t -c user.name=t commit -q -m base
	run env PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work" --root "$O" --entries "$T/reg"
	[ "$status" -eq 0 ]
	[[ "$output" == *"d1"*"PASS"*"DETECTED"* ]]
	[ -z "$(git -C "$O" status --porcelain)" ]
	run env STUB_BLIND=1 PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work" --root "$O" --entries "$T/reg"
	[ "$status" -eq 1 ]
	[[ "$output" == *"MISSED"* ]]
}

@test "runner: a registry directory that does not exist is a usage error" {
	make_repo
	run env PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work" --entries "$T/nope"
	[ "$status" -eq 2 ]
}

@test "runner: an entry needing Postgres is SKIP without a DSN, exit 3 under --strict" {
	make_repo
	printf 'NEEDS=pg\n' >>"$R/scripts/fuzzing/oracle-health/entries.d/e1.conf"
	run env -u KEYORIX_TEST_PG_DSN PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 0 ]
	[[ "$output" == *"SKIP"* ]]
	run env -u KEYORIX_TEST_PG_DSN PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work" --strict
	[ "$status" -eq 3 ]
}

@test "runner: a relative --entries path is resolved before the plant is applied" {
	make_repo
	O="$T/other"
	mkdir -p "$O" "$T/reg"
	printf 'package a\n\nvar Guard = true\n' >"$O/a.go"
	cp "$R/scripts/fuzzing/oracle-health/entries.d/e1.conf" "$T/reg/d1.conf"
	cp "$R/scripts/fuzzing/oracle-health/entries.d/e1.patch" "$T/reg/d1.patch"
	git -C "$O" init -q
	git -C "$O" add -A
	git -C "$O" -c user.email=t@t -c user.name=t commit -q -m base
	cd "$T"
	run env PATH="$T/bin:$PATH" bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work" --root other --entries reg
	[ "$status" -eq 0 ]
	[[ "$output" == *"d1"*"PASS"*"DETECTED"* ]]
	[[ "$output" != *"PLANT-STALE"* ]]
}

@test "runner: --list refuses a registry directory that does not exist" {
	make_repo
	run bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --list --entries "$T/nope"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no registry directory"* ]]
}

# selftest_entry <cmd> <marker>: replace the registry with one self-test entry.
selftest_entry() {
	rm -f "$R"/scripts/fuzzing/oracle-health/entries.d/*
	printf 'KIND=selftest\nCMD=%s\nMARKERS=%s\n' "$1" "$2" >"$R/scripts/fuzzing/oracle-health/entries.d/s1.conf"
	git -C "$R" add -A
	git -C "$R" -c user.email=t@t -c user.name=t commit -q -m selftest
}

@test "runner: a self-test that passes with its marker is DETECTED" {
	make_repo
	selftest_entry "printf -- '--- PASS: TestWanted (0.00s)\nPASS\n'" "--- PASS: TestWanted"
	run bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 0 ]
	[[ "$output" == *"s1"*"DETECTED"* ]]
}

@test "runner: a self-test that passes without its marker is WRONG-MARKER" {
	make_repo
	selftest_entry "printf -- '--- PASS: TestOther (0.00s)\nPASS\n'" "--- PASS: TestWanted"
	run bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 1 ]
	[[ "$output" == *"WRONG-MARKER"*"self-test passed without: --- PASS: TestWanted"* ]]
	[[ "$output" != *"DETECTED"* ]]
}

@test "runner: a self-test with a skipped test is SKIP, not DETECTED, exit 3 under --strict" {
	make_repo
	selftest_entry "printf -- '--- PASS: TestWanted (0.00s)\n--- SKIP: TestVectors (0.00s)\n    x_test.go:1: vectors not downloaded\nPASS\n'" "--- PASS: TestWanted"
	run bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work"
	[ "$status" -eq 0 ]
	[[ "$output" == *"s1"*"SKIP"*"self-test skipped: TestVectors"* ]]
	[[ "$output" != *"DETECTED"* ]]
	run bash "$R/scripts/fuzzing/oracle-health/oracle-health.sh" --workdir "$T/work" --strict
	[ "$status" -eq 3 ]
}
