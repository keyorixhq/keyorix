#!/bin/sh
# Regenerates one tag's Postgres snapshot. Usage (from this repository's root,
# with KEYORIX_TEST_PG_DSN set):
#
#   regen.sh <tag> <tag-checkout> <adapter: v091|v092plus>
#
# <tag-checkout> is a throwaway checkout of <tag>; this script writes into it and
# runs the tag's own core against Postgres, in databases named w6_gen_*, which
# it drops. The output lands in internal/storage/testdata/upgrade-snapshots-pg/<tag>.
set -eu
tag=$1
checkout=$2
adapter=$3
root=$(pwd)
here=$root/internal/storage/testdata/upgrade-snapshots-pg/generator
dst=$checkout/internal/storage

cp "$root/internal/storage/upgrade_snapshot_state_test.go" "$dst/w6_state_a_test.go"
cp "$root/internal/storage/upgrade_pg_state_test.go" "$dst/w6_state_b_test.go"
cp "$here/w6_gen_test.go.txt" "$dst/w6_gen_test.go"
cp "$here/adapt_$adapter.go.txt" "$dst/w6_adapt_test.go"
printf '%s\n%s\n%s\n' "$tag" \
	"$root/internal/storage/testdata/upgrade-snapshots-pg/$tag" \
	"$root/internal/core/testdata/upgrade-fixtures/v095" >"$dst/w6_gen.conf"

go -C "$checkout" test ./internal/storage -run '^TestW6GenPGSnapshot$' -count=1 -timeout 1200s
