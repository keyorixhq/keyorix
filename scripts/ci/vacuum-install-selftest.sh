#!/usr/bin/env bash
# scripts/ci/vacuum-install-selftest.sh -- offline calibration of
# devtools/vacuum/install.sh (VACUUM-FOLLOWUP-1), both directions: green on a
# good download and on a good cache entry, red (exit 1, nothing left installed)
# on every refusal path the installer claims, and a corrupted cache entry is
# deleted and downloaded again exactly once.
#
# No network: the "release" is a directory served through the installer's
# --base-url with a file:// URL, holding a tiny fake `vacuum` that prints a
# version. The installer still checks a real SHA-256 against a real pin file,
# so the refusal paths are the production ones.
#
# Usage: scripts/ci/vacuum-install-selftest.sh   (from anywhere)
# No -e: a failing `[ ... ]` before `assert` must be counted, not abort the run
# (a broken setup step still shows up as failed cases and a non-zero exit).
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# VACUUM_INSTALLER points the test at a mutated copy (mutation proof only).
installer=${VACUUM_INSTALLER:-$(cd "$here/../../devtools/vacuum" && pwd)/install.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

# The same os/arch names install.sh derives from uname.
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "SKIP: unsupported OS $(uname -s)"; exit 0 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "SKIP: unsupported architecture $(uname -m)"; exit 0 ;;
esac
hostkey="sha256_${os}_${arch}"
ver=9.9.9
asset="vacuum_${ver}_${os}_${arch}.tar.gz"

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# mkarchive FILE REPORTED-VERSION: a tar.gz holding a fake `vacuum`.
mkarchive() {
  local stage="$work/stage.$$"
  rm -rf "$stage"
  mkdir -p "$stage"
  printf '#!/bin/sh\necho %s\n' "$2" > "$stage/vacuum"
  chmod 0755 "$stage/vacuum"
  tar -czf "$1" -C "$stage" vacuum
  rm -rf "$stage"
}

# The good release and a different archive that must never be accepted.
mkdir -p "$work/serve/v$ver" "$work/empty"
mkarchive "$work/serve/v$ver/$asset" "$ver"
good=$(sha256 "$work/serve/v$ver/$asset")
mkarchive "$work/other.tar.gz" "$ver.evil"
bad_hash=$(sha256 "$work/other.tar.gz")
zeros=0000000000000000000000000000000000000000000000000000000000000000

# pin FILE LINES...: writes a pin file, one argument per line.
pin() {
  local f=$1
  shift
  printf '%s\n' "$@" > "$f"
}
goodpin() { pin "$1" "# test pin" "version=$ver" "$hostkey=$good" "sha256_plan9_mips=$zeros"; }

# run NAME: runs the installer against $pinfile / $cache / $base; sets $code,
# $stdout, $stderr.
code=0
stdout=
stderr=
run() {
  code=0
  bash "$installer" --pin "$pinfile" --dir "$cache" --base-url "$base" > "$work/out" 2> "$work/err" || code=$?
  stdout=$(cat "$work/out")
  stderr=$(cat "$work/err")
}

# check DESC WANT-EXIT [STDERR-REGEX]
check() {
  local desc=$1 want=$2 rx=${3:-}
  if [ "$code" -ne "$want" ]; then
    fail=$((fail + 1))
    printf 'FAIL: %s: want exit %s, got %s\n%s\n' "$desc" "$want" "$code" "$stderr" >&2
  elif [ -n "$rx" ] && ! printf '%s\n' "$stderr" | grep -qE -- "$rx"; then
    fail=$((fail + 1))
    printf 'FAIL: %s: stderr lacks /%s/\n%s\n' "$desc" "$rx" "$stderr" >&2
  else
    pass=$((pass + 1))
    echo "ok: $desc"
  fi
}

# assert DESC CONDITION-EXIT-STATUS
assert() {
  if [ "$2" -eq 0 ]; then
    pass=$((pass + 1))
    echo "ok: $1"
  else
    fail=$((fail + 1))
    echo "FAIL: $1" >&2
  fi
}

base="file://$work/serve"
pinfile="$work/pin"

# --- green paths -----------------------------------------------------------

cache="$work/c1"
goodpin "$pinfile"
run
check "clean cache, good download installs" 0 "downloading"
if [ "$stdout" = "$cache/vacuum" ]; then assert "stdout is only the binary path" 0; else assert "stdout is only the binary path" 1; fi
if [ "$("$cache/vacuum" version)" = "$ver" ]; then assert "installed binary reports the pinned version" 0; else assert "installed binary reports the pinned version" 1; fi

# A good cache entry is used without touching the network: the base URL now
# serves nothing, so any download would fail.
base="file://$work/empty"
run
check "good cached archive is used without a download" 0
if printf '%s\n' "$stderr" | grep -q downloading; then
  fail=$((fail + 1))
  echo "FAIL: a good cache entry triggered a download" >&2
else
  pass=$((pass + 1))
  echo "ok: no download for a good cache entry"
fi

# --- L1: corrupt cache entry is deleted and downloaded once more -----------

base="file://$work/serve"
cache="$work/c2"
mkdir -p "$cache"
echo "truncated garbage" > "$cache/$asset"
run
check "corrupt cached archive: re-download path taken" 0 "cached .* has SHA-256 .*deleting it and downloading again"
if [ "$(sha256 "$cache/$asset")" = "$good" ]; then assert "the cache entry now holds the verified archive" 0; else assert "the cache entry now holds the verified archive" 1; fi
if [ "$stdout" = "$cache/vacuum" ]; then assert "binary installed after the re-download" 0; else assert "binary installed after the re-download" 1; fi
n=$(printf '%s\n' "$stderr" | grep -c "downloading https\?://\|downloading file://" || true)
if [ "$n" -eq 1 ]; then assert "exactly one download was made" 0; else assert "exactly one download was made" 1; fi

# Fail closed: the cache entry is bad AND the fresh download mismatches too.
cache="$work/c3"
mkdir -p "$cache" "$work/serve-bad/v$ver"
echo "truncated garbage" > "$cache/$asset"
cp "$work/other.tar.gz" "$work/serve-bad/v$ver/$asset"
base="file://$work/serve-bad"
run
check "bad cache and bad fresh download fails closed" 1 "SHA-256 mismatch for freshly downloaded"
if [ ! -e "$cache/$asset" ] && [ ! -e "$cache/vacuum" ]; then assert "nothing is left in the cache after a fresh mismatch" 0; else assert "nothing is left in the cache after a fresh mismatch" 1; fi

# A mismatching fresh download with an empty cache fails the same way.
cache="$work/c4"
run
check "wrong archive on a clean cache is refused" 1 "SHA-256 mismatch"
if [ ! -e "$cache/$asset" ] && [ ! -e "$cache/vacuum" ]; then assert "wrong archive is deleted, no binary installed" 0; else assert "wrong archive is deleted, no binary installed" 1; fi

# The pin itself is wrong (hash of another archive): same refusal.
base="file://$work/serve"
cache="$work/c5"
pin "$pinfile" "version=$ver" "$hostkey=$bad_hash"
run
check "wrong hash in the pin is refused" 1 "SHA-256 mismatch"
if [ ! -e "$cache/$asset" ] && [ ! -e "$cache/vacuum" ]; then assert "wrong-hash pin leaves nothing installed" 0; else assert "wrong-hash pin leaves nothing installed" 1; fi

# A stale binary from an earlier run must not survive a refusal.
cache="$work/c6"
mkdir -p "$cache"
printf '#!/bin/sh\necho stale\n' > "$cache/vacuum"
chmod 0755 "$cache/vacuum"
run
check "refusal with a stale binary present" 1 "SHA-256 mismatch"
if [ ! -e "$cache/vacuum" ]; then assert "stale binary is removed before any refusal" 0; else assert "stale binary is removed before any refusal" 1; fi

# --- L2/L3: pin-file refusals ----------------------------------------------

cache="$work/c7"
pin "$pinfile" "version=$ver" "sha256_plan9_mips=$zeros"
run
check "pin without a line for this os/arch" 1 "has no $hostkey line"

pin "$pinfile" "version=$ver" "$hostkey=$good" "version=1.0.0"
run
check "duplicate version key" 1 "duplicate key version"

pin "$pinfile" "version=$ver" "$hostkey=$good" "$hostkey=$good"
run
check "duplicate hash key (even with the same value)" 1 "duplicate key $hostkey"

pin "$pinfile" "version=$ver" "$hostkey=$good" "$hostkey=$bad_hash"
run
check "duplicate hash key with a different value" 1 "duplicate key $hostkey"

pin "$pinfile" "version = $ver" "$hostkey=$good"
run
check "whitespace around =" 1 "not a KEY=value line"

pin "$pinfile" "version=$ver " "$hostkey=$good"
run
check "trailing whitespace" 1 "not a KEY=value line"

pin "$pinfile" "version=$ver" "$hostkey=$good extra"
run
check "whitespace inside a value" 1 "not a KEY=value line"

pin "$pinfile" "version=$ver" "$hostkey=\"$good\""
run
check "quoted value" 1 "64 lowercase hex digits"

pin "$pinfile" "version=$ver" "$hostkey=$good" "colour=blue"
run
check "unknown key" 1 "unknown key colour"

pin "$pinfile" "version=$ver" "$hostkey=$(printf '%s' "$good" | tr 'a-f' 'A-F')"
run
check "uppercase hex" 1 "64 lowercase hex digits"

pin "$pinfile" "version=$ver" "$hostkey=${good%?}"
run
check "short hash" 1 "64 lowercase hex digits"

pin "$pinfile" "$hostkey=$good"
run
check "no version line" 1 "has no version line"

pin "$pinfile" "version=v$ver" "$hostkey=$good"
run
check "version not X.Y.Z" 1 "version must be X.Y.Z"

# The archive hashes right but its binary reports another version.
mkdir -p "$work/serve-ver/v$ver"
mkarchive "$work/serve-ver/v$ver/$asset" "$ver.evil"
wrongver=$(sha256 "$work/serve-ver/v$ver/$asset")
base="file://$work/serve-ver"
cache="$work/c8"
pin "$pinfile" "version=$ver" "$hostkey=$wrongver"
run
check "binary reporting another version is refused" 1 "contains vacuum"
if [ ! -e "$cache/vacuum" ]; then assert "wrong-version binary is removed" 0; else assert "wrong-version binary is removed" 1; fi

# A download that fails outright.
base="file://$work/empty"
cache="$work/c9"
goodpin "$pinfile"
run
check "missing release asset fails the download" 1 "download failed"

# A pin file that cannot be read.
pinfile="$work/does-not-exist"
run
check "unreadable pin file" 1 "cannot read pin file"

echo "vacuum-install-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
