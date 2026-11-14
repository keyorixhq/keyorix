#!/bin/bash
# Fetches the pinned test tools of mechanism B into a project-local directory (nothing is installed system-wide and
# nothing is added to any SDK build). Usage: fetch-tools.sh <dir>
#   Jazzer 0.30.0 standalone (macOS universal tarball) - coverage-guided fuzzing of JVM code
#   Gson 2.15.0                                          - TEST-ONLY RFC 8259 reference parser
#   JSONTestSuite at 1ef36fa                             - y_ / n_ / i_ corpus (github.com/nst/JSONTestSuite)
set -eu
DIR=${1:?usage: fetch-tools.sh <dir>}
mkdir -p "$DIR"
cd "$DIR"
fetch() { # url file sha256
  if [ ! -f "$2" ]; then curl -fsSL -o "$2" "$1"; fi
  got=$(shasum -a 256 "$2" | cut -d' ' -f1)
  if [ "$got" != "$3" ]; then echo "SHA-256 mismatch for $2: $got" >&2; rm -f "$2"; exit 1; fi
}
fetch https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v0.30.0/jazzer-macos.tar.gz jazzer-macos.tar.gz 6239e2b2b8d626c287fd8a50376315f00ef4310e3f29e96315cd6e60911563c8
fetch https://repo1.maven.org/maven2/com/google/code/gson/gson/2.15.0/gson-2.15.0.jar gson-2.15.0.jar 96d3dd843dc2911de01cdabcd50064cb9e860353102a0a78c96fd833d396fc7d
fetch https://github.com/nst/JSONTestSuite/archive/1ef36fa01286573e846ac449e8683f8833c5b26a.tar.gz jsonTestSuite.tar.gz 32ab2fb37cc26679dbd9164dbb7053bcef10134643d53cb0cef45de7680dcdcc
mkdir -p jazzer jts
tar -xzf jazzer-macos.tar.gz -C jazzer
tar -xzf jsonTestSuite.tar.gz -C jts
echo "tools ready in $DIR (jazzer/, gson-2.15.0.jar, jts/JSONTestSuite-*/test_parsing)"
