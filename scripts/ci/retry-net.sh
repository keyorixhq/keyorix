#!/usr/bin/env bash
# retry-net.sh: run a command and retry it ONLY when it failed on a transient
# network error from a remote proxy or registry (CI-PARITY-1, 2026-10-25).
#
#   scripts/ci/retry-net.sh go mod download
#   scripts/ci/retry-net.sh docker compose up -d
#
# Why: in the merge queue (27 Sep - 24 Oct) jobs failed on proxy.golang.org
# ("TLS handshake timeout" 3 Oct, "stream error ... INTERNAL_ERROR" 20 Oct) and
# on Docker Hub ("500 Internal Server Error", "unauthorized: authentication
# required" 23 Oct), each time failing the whole queue round. The fixtures in
# testdata/retry-net/ are those real error lines.
#
# Rules:
#   - At most 3 attempts (RETRY_NET_ATTEMPTS may lower it, never raise it),
#     back-off RETRY_NET_DELAYS seconds between them (default "15 45").
#   - A retry happens only when the failed attempt's stderr has a line that
#     matches a known network-error shape AND names a remote https URL or
#     registry, never localhost. Anything else (a compile error, a failing
#     test, a 404 for a module that does not exist) fails at once with the
#     command's own exit code: a deterministic failure is never retried and a
#     flaky test is never hidden behind a retry.
#   - Integrity errors are never retried, whatever else the output says: a
#     go.sum "checksum mismatch" / "SECURITY ERROR", "missing go.sum entry",
#     "updates to go.mod needed". Verification is the command's own (go, docker);
#     this wrapper never changes GOFLAGS, GONOSUMDB, GOPROXY or any flag.
#   - stdout passes through untouched (so `out=$(retry-net.sh cmd)` works);
#     stderr is passed through and also scanned. Each retry prints a
#     ::warning:: annotation naming the matched line, so a retry is visible in
#     the run summary instead of silent.
set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: retry-net.sh <command> [args...]" >&2
  exit 2
fi

max=3
attempts=${RETRY_NET_ATTEMPTS:-3}
case "$attempts" in
  '' | *[!0-9]*) attempts=3 ;;
esac
if [ "$attempts" -gt "$max" ]; then attempts=$max; fi
if [ "$attempts" -lt 1 ]; then attempts=1; fi
read -r -a delays <<< "${RETRY_NET_DELAYS:-15 45}"

# Known transient shapes. Each requires a remote URL or a registry daemon
# reply on the same line; lines naming localhost are dropped below.
net_re='(Get|Head|read|Post) "https://[^"]+": .*([Tt]imeout|EOF|reset|refused|request canceled|stream error|INTERNAL_ERROR|no such host|server misbehaving|Temporary failure)'
net_re+='|unexpected status from (HEAD|GET) request to https://[^ ]+: (5[0-9][0-9]|429)'
net_re+='|Error response from daemon: (unauthorized: authentication required|toomanyrequests|received unexpected HTTP status: 5[0-9][0-9]|Get "https://)'
net_re+='|toomanyrequests: You have reached your (pull|unauthenticated pull) rate limit'
local_re='//(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)[:/]'
never_re='SECURITY ERROR|checksum mismatch|missing go\.sum entry|updates to go\.mod needed|verifying .*: .*mismatch'

log=$(mktemp)
trap 'rm -f "$log"' EXIT

i=1
while :; do
  : > "$log"
  # stdout -> fd 3 (the caller's stdout, untouched); stderr -> tee -> log + stderr.
  { "$@" 2>&1 1>&3 3>&- | tee -a "$log" 1>&2 3>&-; } 3>&1
  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if grep -qE "$never_re" "$log"; then
    echo "retry-net: '$1' failed (exit $rc) on an integrity error; not retrying" >&2
    exit "$rc"
  fi
  hit=$(grep -E "$net_re" "$log" | grep -vE "$local_re" | head -n 1)
  if [ -z "$hit" ]; then
    exit "$rc"
  fi
  if [ "$i" -ge "$attempts" ]; then
    echo "retry-net: '$1' failed (exit $rc) on a network error after $i attempt(s); giving up: $hit" >&2
    exit "$rc"
  fi
  delay=15
  if [ "${#delays[@]}" -ge "$i" ]; then delay=${delays[$((i - 1))]}; fi
  case "$delay" in '' | *[!0-9]*) delay=15 ;; esac
  # Keep the annotation one line and short; the full line is in the log above.
  echo "::warning::retry-net: attempt $i/$attempts of '$1' failed on a network error, retrying in ${delay}s: ${hit:0:300}" >&2
  sleep "$delay"
  i=$((i + 1))
done
