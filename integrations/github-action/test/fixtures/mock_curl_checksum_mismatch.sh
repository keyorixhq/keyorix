#!/usr/bin/env bash
# Mock curl used by entrypoint_test.sh's #175 case: serves a fake binary for
# the release download URL, and a checksums.txt whose recorded hash
# deliberately does NOT match that binary's real hash, simulating
# in-transit tampering/corruption.
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) ;;
esac
binary_name="keyorix_${os}_${arch}"

out=""
url=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -o) out="${args[$((i + 1))]}" ;;
    http*) url="${args[$i]}" ;;
    *) ;;
  esac
done

case "$url" in
  */checksums.txt)
    echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  ${binary_name}"
    ;;
  *) printf 'not-the-real-binary-contents' >"$out" ;;
esac
