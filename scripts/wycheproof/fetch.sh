#!/bin/bash
# fetch.sh -- download the pinned Wycheproof vectors used by internal/wycheproof
# and verify every file against internal/wycheproof/wvec/SHA256SUMS.
#
# Usage: scripts/wycheproof/fetch.sh [dest-dir]
#   dest-dir defaults to internal/wycheproof/testdata/vectors (git-ignored).
#   WYCHEPROOF_DIR=<dest-dir> go test ./internal/wycheproof/... uses another dir.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUMS="$ROOT/internal/wycheproof/wvec/SHA256SUMS"
DEST="${1:-${WYCHEPROOF_DIR:-$ROOT/internal/wycheproof/testdata/vectors}}"
COMMIT="$(sed -n 's/^# C2SP\/wycheproof \([0-9a-f]\{40\}\),.*/\1/p' "$SUMS")"
[ -n "$COMMIT" ] || { echo "no commit line in $SUMS" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$DEST"
fail=0
while read -r want name; do
  case "$want" in ''|'#'*) continue ;; esac
  out="$DEST/$name"
  if [ -f "$out" ] && [ "$(sha256_of "$out")" = "$want" ]; then
    echo "ok (cached) $name"
    continue
  fi
  tmp="$(mktemp)"
  curl -fsSL "https://raw.githubusercontent.com/C2SP/wycheproof/$COMMIT/testvectors_v1/$name" -o "$tmp"
  got="$(sha256_of "$tmp")"
  if [ "$got" != "$want" ]; then
    echo "CHECKSUM MISMATCH $name: got $got want $want" >&2
    rm -f "$tmp"
    fail=1
    continue
  fi
  mv "$tmp" "$out"
  echo "ok $name"
done < "$SUMS"
exit $fail
