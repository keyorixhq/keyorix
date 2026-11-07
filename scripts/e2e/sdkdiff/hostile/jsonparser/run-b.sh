#!/bin/bash
# Mechanism B: builds the harness against a keyorix-sdks checkout and runs the plain driver (always) and Jazzer (if present).
# Usage: run-b.sh <tools dir> <keyorix-sdks checkout> <work dir> [seeds=20000] [jazzer seconds=60]
set -eu
TOOLS=$(cd "$1" && pwd); SDKS=$(cd "$2" && pwd); W=$3; SEEDS=${4:-20000}; JSEC=${5:-60}
HERE=$(cd "$(dirname "$0")" && pwd)
JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}
JAVAC=${JAVAC:-/opt/homebrew/opt/openjdk/bin/javac}
mkdir -p "$W"; W=$(cd "$W" && pwd)
rm -rf "$W/classes"; mkdir -p "$W/classes"
CP=$TOOLS/gson-2.15.0.jar:$TOOLS/jazzer/jazzer_standalone.jar
"$JAVAC" --release 17 -nowarn -d "$W/classes" -cp "$CP" "$SDKS"/java/src/main/java/com/keyorix/*.java "$HERE"/HostileJson.java "$HERE"/PlainFuzz.java
CORPUS=$(echo "$TOOLS"/jts/JSONTestSuite-*/test_parsing)
nice -n 10 "$JAVA_HOME/bin/java" -Xmx512m -cp "$W/classes:$TOOLS/gson-2.15.0.jar" com.keyorix.PlainFuzz 1 "$SEEDS" "$CORPUS" >"$W/plain.txt" 2>&1 || true
echo "plain driver: $W/plain.txt"
if [ -x "$TOOLS/jazzer/jazzer" ]; then
  (cd "$W" && JAVA_HOME=$JAVA_HOME nice -n 10 "$TOOLS/jazzer/jazzer" --cp="$W/classes:$TOOLS/gson-2.15.0.jar" --target_class=com.keyorix.HostileJson \
    --instrumentation_includes='com.keyorix.**' --keep_going=10 -max_len=4096 -max_total_time="$JSEC" -jvm_args=-Xmx512m >jazzer.txt 2>&1 || true)
  echo "jazzer: $W/jazzer.txt"
fi
