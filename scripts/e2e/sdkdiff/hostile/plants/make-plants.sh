#!/bin/bash
# Usage: make-plants.sh <keyorix-sdks checkout> <out dir> <build-drivers.sh dir>
# Copies the SDK tree once per plant into <out>/PHn, applies plants/plant.py and builds the drivers for each copy.
# The checkout itself is never modified.
set -eu
SRC=$(cd "$1" && pwd)
OUT=$2
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(cd "$3" && pwd)
mkdir -p "$OUT"
for P in PH0 PH1 PH2 PH3 PH4 PH5 PH6; do
  rm -rf "$OUT/$P" "$OUT/build-$P"
  mkdir -p "$OUT/$P"
  for d in go node python java; do cp -R "$SRC/$d" "$OUT/$P/$d"; done
  python3 -I "$HERE/plant.py" "$P" "$OUT/$P"
  "$BUILD/build-drivers.sh" "$OUT/$P" "$OUT/build-$P" >/dev/null
  echo "planted $P"
done
