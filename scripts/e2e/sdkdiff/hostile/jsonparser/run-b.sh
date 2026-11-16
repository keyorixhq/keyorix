#!/bin/bash
# Mechanism B: builds the harness against a keyorix-sdks checkout and runs the plain driver (always) and Jazzer (if present).
# Usage: run-b.sh <tools dir> <keyorix-sdks checkout> <work dir> [seeds=20000] [jazzer seconds=60]
set -eu
TOOLS=$(cd "$1" && pwd); SDKS=$(cd "$2" && pwd); W=$3; SEEDS=${4:-20000}; JSEC=${5:-60}
HERE=$(cd "$(dirname "$0")" && pwd)
# JDK: JAVA_HOME if set, else the one whose javac is on PATH.
if [ -z "${JAVA_HOME:-}" ]; then
  JC=$(command -v javac) || { echo "run-b.sh: set JAVA_HOME or put javac on PATH" >&2; exit 2; }
  JAVA_HOME=$(cd "$(dirname "$(readlink -f "$JC")")/.." && pwd)
fi
JAVAC=${JAVAC:-$JAVA_HOME/bin/javac}
mkdir -p "$W"; W=$(cd "$W" && pwd)
rm -rf "$W/classes"; mkdir -p "$W/classes"
CP=$TOOLS/gson-2.15.0.jar:$TOOLS/jazzer/jazzer_standalone.jar
"$JAVAC" --release 17 -nowarn -d "$W/classes" -cp "$CP" "$SDKS"/java/src/main/java/com/keyorix/*.java "$HERE"/HostileJson.java "$HERE"/PlainFuzz.java
shopt -s nullglob
CORPORA=("$TOOLS"/jts/JSONTestSuite-*/test_parsing)
shopt -u nullglob
if [ "${#CORPORA[@]}" -ne 1 ]; then
  echo "run-b.sh: expected one JSONTestSuite corpus under $TOOLS/jts, found ${#CORPORA[@]} (run fetch-tools.sh)" >&2
  exit 2
fi
CORPUS=${CORPORA[0]}
RC=0
PRC=0
nice -n 10 "$JAVA_HOME/bin/java" -Xmx512m -cp "$W/classes:$TOOLS/gson-2.15.0.jar" com.keyorix.PlainFuzz 1 "$SEEDS" "$CORPUS" >"$W/plain.txt" 2>&1 || PRC=$?
echo "plain driver: exit $PRC, $W/plain.txt"
[ "$PRC" -eq 0 ] || RC=$PRC
if [ -x "$TOOLS/jazzer/jazzer" ]; then
  (cd "$W" && JAVA_HOME=$JAVA_HOME nice -n 10 "$TOOLS/jazzer/jazzer" --cp="$W/classes:$TOOLS/gson-2.15.0.jar" --target_class=com.keyorix.HostileJson \
    --instrumentation_includes='com.keyorix.**' --keep_going=10 -max_len=4096 -max_total_time="$JSEC" -jvm_args=-Xmx512m >jazzer.txt 2>&1) || JRC=$?
  echo "jazzer: exit ${JRC:-0}, $W/jazzer.txt"
  [ "${JRC:-0}" -eq 0 ] || RC=${JRC}
fi
# non-zero when either fuzzer reported a finding or failed; both outputs are kept above
exit "$RC"
