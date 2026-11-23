#!/usr/bin/env bash
# Installs the vacuum OpenAPI linter release pinned in devtools/vacuum/VACUUM.pin
# (VACUUM-BIN-1). Used by ci.yml's openapi-lint job and by `make openapi-lint`.
#
#   devtools/vacuum/install.sh [--pin FILE] [--dir DIR]
#
# Downloads vacuum_<version>_<os>_<arch>.tar.gz from the daveshanley/vacuum
# GitHub release for this machine's OS/arch into DIR (default .cache/vacuum,
# gitignored), checks its SHA-256 against the sha256_<os>_<arch> line of the
# pin file, extracts the `vacuum` binary to DIR/vacuum and checks that
# `vacuum version` reports the pinned version. Prints DIR/vacuum on success.
#
# Fails closed (exit 1) on: a hash mismatch, an OS/arch with no pin line, a
# malformed pin file, a download that still fails after curl's retries, or a
# binary that reports another version. On a mismatch the archive is deleted, so
# neither a bad download nor a bad cache entry is used again.
#
# The pin file is the only trust anchor: nothing fetched at run time (the
# release's checksums.txt, the archive itself) is believed on its own. The
# archive is re-hashed on every run, also when DIR came from the CI cache, and
# the binary is always re-extracted from the verified archive, so a cached
# binary is never trusted as such.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pin="$here/VACUUM.pin"
dir=.cache/vacuum
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pin) pin=${2:?--pin needs a file}; shift 2 ;;
    --dir) dir=${2:?--dir needs a directory}; shift 2 ;;
    *) echo "usage: devtools/vacuum/install.sh [--pin FILE] [--dir DIR]" >&2; exit 2 ;;
  esac
done

fail() {
  echo "::error::devtools/vacuum/install.sh: $*" >&2
  exit 1
}

[ -r "$pin" ] || fail "cannot read pin file $pin"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

# No associative arrays: macOS ships bash 3.2.
version=
want=
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  case "$line" in
    '' | '#'*) continue ;;
  esac
  [[ "$line" =~ ^([a-z0-9_]+)=([^[:space:]]+)$ ]] || fail "$pin:$lineno: not a KEY=value line"
  key=${BASH_REMATCH[1]}
  value=${BASH_REMATCH[2]}
  case "$key" in
    version)
      [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "$pin:$lineno: version must be X.Y.Z"
      version=$value
      ;;
    sha256_*)
      [[ "$value" =~ ^[0-9a-f]{64}$ ]] || fail "$pin:$lineno: $key must be 64 lowercase hex digits"
      if [ "$key" = "sha256_${os}_${arch}" ]; then want=$value; fi
      ;;
    *) fail "$pin:$lineno: unknown key $key" ;;
  esac
done < "$pin"
[ -n "$version" ] || fail "$pin has no version line"

[ -n "$want" ] || fail "$pin has no sha256_${os}_${arch} line; refusing to install an unverified vacuum"

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

asset="vacuum_${version}_${os}_${arch}.tar.gz"
url="https://github.com/daveshanley/vacuum/releases/download/v${version}/${asset}"
mkdir -p "$dir"
archive="$dir/$asset"
# Remove the previous run's binary first: if anything below fails, no
# unverified vacuum is left at DIR/vacuum for a later step to pick up.
rm -f "$dir/vacuum"

if [ ! -f "$archive" ]; then
  # Timeouts detect a hung connection; the limits are generous (the archive is
  # ~25 MB). curl retries only transient failures (timeouts, 408/429/5xx,
  # refused connections), never a 404.
  curl --proto '=https' --tlsv1.2 -fsSL \
    --connect-timeout 30 --max-time 300 \
    --retry 3 --retry-delay 10 --retry-connrefused \
    -o "$archive.part" "$url" || { rm -f "$archive.part"; fail "download failed: $url"; }
  mv "$archive.part" "$archive"
fi

got=$(sha256 "$archive")
if [ "$got" != "$want" ]; then
  rm -f "$archive"
  fail "SHA-256 mismatch for $asset: got $got, $pin pins $want"
fi

tar -xzf "$archive" -C "$dir" vacuum
chmod 0755 "$dir/vacuum"
reported=$("$dir/vacuum" version)
if [ "$reported" != "$version" ]; then
  rm -f "$dir/vacuum"
  fail "$asset contains vacuum $reported, $pin pins $version"
fi

echo "$dir/vacuum"
