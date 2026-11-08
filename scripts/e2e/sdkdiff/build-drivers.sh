#!/bin/bash
# Build the SDK drivers into <out-dir>.  Usage: build-drivers.sh <keyorix-sdks checkout> <out-dir>
# Cross-compile the Go driver with GOOS/GOARCH in the environment (e.g. to run on pve01).
# Node and Python drivers need no build; Java is compiled with javac (SDKDIFF_JAVAC overrides the path).
set -eu
SDKS=$(cd "$1" && pwd)
OUT=$2
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd) # absolute: the go build below runs after a cd into drivers/go

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$HERE/drivers/go/go.mod" "$tmp/go.mod"
(cd "$tmp" && GOWORK=off go mod edit -replace "github.com/keyorixhq/keyorix-sdks/go=$SDKS/go")
(cd "$HERE/drivers/go" && CGO_ENABLED=0 GOWORK=off go build -modfile="$tmp/go.mod" -o "$OUT/driver-go" .)
echo "built $OUT/driver-go"

JAVAC=${SDKDIFF_JAVAC:-}
if [ -z "$JAVAC" ]; then
  for c in javac /opt/homebrew/opt/openjdk/bin/javac; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -version >/dev/null 2>&1; then JAVAC=$c; break; fi
  done
fi
if [ -n "$JAVAC" ]; then
  rm -rf "$OUT/java-classes"
  mkdir -p "$OUT/java-classes"
  "$JAVAC" --release 11 -d "$OUT/java-classes" "$SDKS"/java/src/main/java/com/keyorix/*.java "$HERE/drivers/java/Driver.java"
  echo "built $OUT/java-classes"
else
  echo "no javac found: Java driver skipped"
fi
