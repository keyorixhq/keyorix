#!/usr/bin/env bash
# Writes one ~6 MB JSON array of numbers into $1 as a go fuzz corpus file (see
# bounded-json-decode-inner-cap.conf, keyorix#4740).
set -eu
dest=$1
awk 'BEGIN { printf "go test fuzz v1\n[]byte(\"["; for (i = 0; i < 3000000; i++) printf "1,"; print "1]\")" }' >"$dest/orh1-big-array"
