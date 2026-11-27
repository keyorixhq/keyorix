#!/usr/bin/env bash
# lib.sh -- the pure parts of oracle-health.sh: entry parsing, run classification,
# marker matching and the verdict table. Sourced by the runner and by
# tests/oracle_health.bats (which stubs `go`); nothing here runs a test, touches
# git or writes outside the files it is handed.

# Keys an entries.d/<id>.conf may set (anything else is refused, so a typo cannot
# silently become "no marker required").
OH_KEYS="FAMILY DESC KIND MODULE_DIR PKG RUN TARGET NEEDS MARKERS PATCH REPLAY_GEN REPLAY_DIR TIMEOUT KNOWN_BLIND HEAVY CMD VERIFIED"

# oh_parse_conf <file>: read KEY=VALUE lines (no shell evaluation, '#' comments)
# into OH_<KEY> variables. Returns 1 and prints the reason on a bad line.
oh_parse_conf() {
	local file=$1 line key val n=0 k ok
	for k in $OH_KEYS; do unset "OH_$k"; done
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		case $line in '' | '#'*) continue ;; esac
		case $line in *=*) ;; *)
			echo "$file:$n: not KEY=VALUE: $line"
			return 1
			;;
		esac
		key=${line%%=*}
		val=${line#*=}
		ok=0
		for k in $OH_KEYS; do [ "$k" = "$key" ] && ok=1; done
		if [ $ok = 0 ]; then
			echo "$file:$n: unknown key $key"
			return 1
		fi
		printf -v "OH_$key" '%s' "$val"
	done <"$file"
	: "${OH_KIND:=plant}" "${OH_MODULE_DIR:=.}" "${OH_NEEDS:=none}" "${OH_TIMEOUT:=300}" "${OH_HEAVY:=0}"
	case $OH_KIND in
	plant) [ -n "${OH_PKG:-}" ] && [ -n "${OH_RUN:-}" ] && [ -n "${OH_MARKERS:-}" ] || {
		echo "$file: KIND=plant needs PKG, RUN and MARKERS"
		return 1
	} ;;
	selftest) [ -n "${OH_CMD:-}" ] && [ -n "${OH_MARKERS:-}" ] || {
		echo "$file: KIND=selftest needs CMD and MARKERS"
		return 1
	} ;;
	*)
		echo "$file: KIND must be plant or selftest"
		return 1
		;;
	esac
	case $OH_NEEDS in none | pg | pg-superuser) ;; *)
		echo "$file: NEEDS must be none, pg or pg-superuser"
		return 1
		;;
	esac
	return 0
}

# oh_classify_run <go-test-exit-code> <logfile>: print how one `go test -v` run
# ended: PASS, FAIL, SKIP (the harness skipped itself) or ERROR (did not build, or
# the -run regex matched nothing, so "green" would mean nothing).
oh_classify_run() {
	local rc=$1 log=$2
	if grep -qE '\[(build|setup) failed\]|no tests to run|no test files' "$log"; then
		echo ERROR
		return
	fi
	if [ "$rc" -ne 0 ]; then
		echo FAIL
		return
	fi
	# exit 0: a top-level SKIP with no passing subtest or test is a skip, not a pass.
	if grep -qE '^--- SKIP' "$log" && ! grep -qE '^[[:space:]]*--- PASS' "$log"; then
		echo SKIP
		return
	fi
	if ! grep -qE '^[[:space:]]*--- PASS' "$log"; then
		echo ERROR
		return
	fi
	echo PASS
}

# oh_markers_match <logfile> <markers>: succeed only when every marker (separated
# by ' || ', matched as a fixed string) occurs in the log.
oh_markers_match() {
	local log=$1 markers=$2 m rest=$2
	[ -n "$markers" ] || return 1
	while [ -n "$rest" ]; do
		case $rest in
		*' || '*)
			m=${rest%%' || '*}
			rest=${rest#*' || '}
			;;
		*)
			m=$rest
			rest=
			;;
		esac
		grep -qF -- "$m" "$log" || return 1
	done
	return 0
}

# oh_verdict <control> <planted> <known_blind>
#   control: PASS FAIL SKIP ERROR NA (selftest entries have no separate control: NA)
#   planted: DETECTED (failed and every marker present) WRONGFAIL (failed, marker
#            missing) PASS SKIP ERROR NOAPPLY
# Prints "<VERDICT> <ok|bad>"; ok means the entry does not fail the run.
oh_verdict() {
	local control=$1 planted=$2 blind=${3:-}
	case $control in
	SKIP)
		echo "SKIP ok"
		return
		;;
	PASS | NA) ;;
	*)
		echo "CONTROL-RED bad"
		return
		;;
	esac
	case $planted in
	NOAPPLY) echo "PLANT-STALE bad" ;;
	ERROR) echo "PLANT-BROKEN bad" ;;
	SKIP) echo "SKIP ok" ;;
	DETECTED)
		if [ -n "$blind" ]; then echo "BLIND-FIXED bad"; else echo "DETECTED ok"; fi
		;;
	WRONGFAIL) echo "WRONG-MARKER bad" ;;
	PASS | FAIL)
		if [ -n "$blind" ]; then echo "KNOWN-BLIND ok"; else echo "MISSED bad"; fi
		;;
	*) echo "PLANT-BROKEN bad" ;;
	esac
}

# oh_exit_code <strict 0|1> <bad-count> <skip-count>
oh_exit_code() {
	if [ "$2" -gt 0 ]; then
		echo 1
	elif [ "$1" = 1 ] && [ "$3" -gt 0 ]; then
		echo 3
	else
		echo 0
	fi
}
