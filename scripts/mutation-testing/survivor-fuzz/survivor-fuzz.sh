#!/usr/bin/env bash
# survivor-fuzz.sh: take one SURVIVING gremlins mutant and try to find an input
# that tells the original function from the mutated one.
#
#   survivor-fuzz.sh [--repo DIR] [--fuzztime 5m] [--out DIR] [--parallel 2]
#                    [--pkg internal/core] "<TYPE> <file>:<line>:<col>"
#
# e.g.  survivor-fuzz.sh --repo ~/proj/keyorix "CONDITIONALS_BOUNDARY access_review.go:90:42"
#
# The survivor id is what gremlins prints ("LIVED <TYPE> at <file>:<l>:<c>").
# NOTE: the position must be read against the SAME commit the mutation run used;
# a survivor list from an older commit maps to different lines on newer code.
#
# How it works (no second copy of the package; the checkout is touched only by
# two zz_sf_* test files, removed on exit):
#   1. mutate -clone writes the ONE enclosing function, mutated and renamed
#      <Name>__mut, into <pkg>/zz_sf_clone_test.go (same package, so it reaches
#      unexported helpers). goimports fixes its imports.
#   2. the hand-written harness harnesses/<Name>_test.go.txt (it runs <Name> and
#      <Name>__mut on identical fresh state and compares what they return and
#      what they leave behind) is copied in as zz_sf_harness_test.go.
#   3. `go test -fuzz` runs the harness for --fuzztime.
# Verdict word (last line of stdout, also in <out>/<id>.verdict):
#   killed-by-input    the fuzzer found an input where original and mutant
#                      differ; the input is saved under <out>/<id>/ and is a
#                      ready regression-test seed
#   likely-equivalent  no difference found in --fuzztime (NOT a proof)
#   harness-missing    no harness for the enclosing function, or it did not build
#   no-node            the position maps to no mutable node at this commit
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
PATH="$PATH:$(go env GOPATH)/bin"
command -v goimports >/dev/null || { echo "goimports not found: go install golang.org/x/tools/cmd/goimports@latest" >&2; exit 2; }
repo="" fuzztime=5m out="" parallel=2 pkg=internal/core
while [ $# -gt 1 ]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --fuzztime) fuzztime="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --parallel) parallel="$2"; shift 2 ;;
    --pkg) pkg="$2"; shift 2 ;;
    *) echo "unknown flag $1" >&2; exit 2 ;;
  esac
done
[ $# -eq 1 ] || { sed -n 2,8p "$0" >&2; exit 2; }
[ -n "$repo" ] || repo="$(cd "$here/../../.." && pwd)"
read -r typ posfull <<<"$1"
file="${posfull%%:*}"; rest="${posfull#*:}"; line="${rest%%:*}"; col="${rest#*:}"
id="${typ}-${file%.go}-${line}-${col}"
: "${out:=$here/results}"
mkdir -p "$out"

verdict() { echo "$1" >"$out/$id.verdict"; echo "$id $1"; exit 0; }

mutate="$(mktemp -d)/mutate"
(cd "$here" && go build -o "$mutate" ./mutate) || { echo "cannot build mutate" >&2; exit 2; }

src="$repo/$pkg/$file"
desc="$("$mutate" -file "$src" -line "$line" -col "$col" -type "$typ")" || verdict no-node
fn="${desc%%:*}"
name="${fn##*.}"
harness="$here/harnesses/${name}_test.go.txt"
[ -f "$harness" ] || { echo "$id: $desc (no harness for $name)"; verdict harness-missing; }

cleanup() { rm -f "$repo/$pkg/zz_sf_clone_test.go" "$repo/$pkg/zz_sf_harness_test.go"; }
trap cleanup EXIT
"$mutate" -file "$src" -line "$line" -col "$col" -type "$typ" -clone "$repo/$pkg/zz_sf_clone_test.go" >/dev/null || verdict no-node
goimports -w "$repo/$pkg/zz_sf_clone_test.go" || verdict harness-missing
cp "$harness" "$repo/$pkg/zz_sf_harness_test.go"

fuzzfn="$(grep -o 'func FuzzSF_[A-Za-z0-9_]*' "$harness" | head -1 | sed 's/func //')"
rm -rf "$repo/$pkg/testdata/fuzz/$fuzzfn"
echo "$id: $desc (harness $fuzzfn, $fuzztime)"
log="$out/$id.log"
(cd "$repo" && go test "./$pkg" -run '^$' -fuzz "^${fuzzfn}\$" -fuzztime "$fuzztime" -parallel "$parallel" >"$log" 2>&1)
st=$?
if [ $st -ne 0 ] && grep -q '^FAIL\s.*\[build failed\]\|^# ' "$log" && ! grep -q 'Failing input' "$log"; then
  echo "build problem, see $log" >&2; verdict harness-missing
fi
if [ $st -ne 0 ] && grep -q -- '--- FAIL' "$log"; then
  mkdir -p "$out/$id"
  # a failure on a seed (f.Add) is not saved by Go under testdata/fuzz; keep the log line
  grep -m1 'ORIG' "$log" >"$out/$id/failing-observation.txt" || true
  if [ -n "$(ls "$repo/$pkg/testdata/fuzz/$fuzzfn" 2>/dev/null)" ]; then
    cp "$repo/$pkg/testdata/fuzz/$fuzzfn"/* "$out/$id/"
    rm -rf "$repo/$pkg/testdata/fuzz/$fuzzfn"
  fi
  head -1 "$out/$id/failing-observation.txt"
  verdict killed-by-input
fi
verdict likely-equivalent
