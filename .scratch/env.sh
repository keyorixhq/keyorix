#!/usr/bin/env bash
# Shared environment for RVF1 go runs. Source this.
export GOCACHE=/mnt/data/wave4/gocache
export GOMODCACHE=/mnt/data/wave4/gomod
export TMPDIR=/mnt/data/wave4/tmp
export GOMAXPROCS=2
export GOFLAGS=
# KEYORIX_TEST_PG_DSN is inherited from the environment if set.
