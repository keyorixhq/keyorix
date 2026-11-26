#!/usr/bin/env bash
# Writes the replay corpus of the pg-upgrade-unlock-stop entry into $1 (the
# package's testdata/fuzz/FuzzUpgradePGInterrupted). Arguments of the fuzz func:
# sel uint8 (source index 5 = v0.96.3), stop uint16 (stopAfter = stop%240+1), data.
set -eu
dest=$1
for stop in $(seq 84 104); do
	printf 'go test fuzz v1\nbyte(%s)\nuint16(%s)\n[]byte("")\n' "'\\x05'" "$stop" >"$dest/orh1-sel5-stop$stop"
done
