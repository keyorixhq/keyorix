#!/usr/bin/env bash
# Mock curl used by entrypoint_test.sh's #177/#466 cases: entrypoint.sh's
# install_cli (#179) verifies an already-on-PATH `keyorix` binary's SHA-256
# against the pinned version's published checksums.txt before reusing it. To
# exercise that reuse path (and avoid a real network install) without
# actually needing a real release, this serves a checksums.txt whose
# recorded hash matches the SHA-256 of $MOCK_KEYORIX_PATH, which the test
# script points at its own mock_keyorix(.sh) fixture already placed on PATH.
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) ;;
esac
binary_name="keyorix_${os}_${arch}"

for arg in "$@"; do
  case "$arg" in
    */checksums.txt)
      if command -v sha256sum >/dev/null 2>&1; then
        sum="$(sha256sum "$MOCK_KEYORIX_PATH" | awk '{print $1}')"
      else
        sum="$(shasum -a 256 "$MOCK_KEYORIX_PATH" | awk '{print $1}')"
      fi
      echo "${sum}  ${binary_name}"
      ;;
    http*)
      echo "mock_curl_checksum_match: unexpected download URL ${arg} (existing binary should have been reused, not downloaded)" >&2
      exit 1
      ;;
    *) ;;
  esac
done
