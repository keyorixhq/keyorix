#!/usr/bin/env bash
# run.sh LOGFILE -- CMD ARGS...   : runs CMD, tees to LOGFILE, prints exit + tail + FAIL/panic grep
export GOCACHE=/mnt/data/wave4/gocache
export GOMODCACHE=/mnt/data/wave4/gomod
export TMPDIR=/mnt/data/wave4/tmp
export GOMAXPROCS=2
export GOFLAGS=
export KEYORIX_TEST_PG_DSN="postgres://difffuzz:difffuzz@192.168.10.34:5432/difffuzz?sslmode=disable"
log="$1"; shift
[ "$1" = "--" ] && shift
nice -n 10 "$@" > "$log" 2>&1
rc=$?
echo "EXITCODE=$rc"
echo "---- grep FAIL/panic/new interesting ----"
grep -nE '^(--- FAIL|FAIL|panic|.*new interesting|.*elapsed:.*execs)' "$log" | tail -20
echo "---- tail ----"
tail -8 "$log"
exit 0
