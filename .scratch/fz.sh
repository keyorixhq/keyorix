#!/usr/bin/env bash
# Wrapper: pins caches/tmp/limits per task runtime rules. Args passed to the command.
export GOCACHE=/mnt/data/wave4/gocache
export GOMODCACHE=/mnt/data/wave4/gomod
export TMPDIR=/mnt/data/wave4/tmp
export GOMAXPROCS=2
export GOFLAGS=
export KEYORIX_TEST_PG_DSN="postgres://difffuzz:difffuzz@192.168.10.34:5432/difffuzz?sslmode=disable"
exec nice -n 10 "$@"
