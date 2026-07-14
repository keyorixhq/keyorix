#!/usr/bin/env bash
# entrypoint_test.sh — regression test for #241: entrypoint.sh's first-boot admin
# bootstrap used to pass the admin password to wget via --post-data, which puts it
# straight into the process's argv — visible to any process/user sharing the
# container's PID namespace via `ps`/`/proc/<pid>/cmdline` on literally every
# production first boot. It must now be written to a private (0600, owner-only)
# temp file and sent via --post-file instead.
#
# entrypoint.sh is a top-to-bottom `/bin/sh` script (no functions, no
# BASH_SOURCE guard), so it can't be sourced side-effect-free the way
# integrations/github-action/entrypoint_test.sh sources its target. Instead this
# test extracts the exact bootstrap `if [ -n "$KEYORIX_ADMIN_PASSWORD" ]; ...; fi`
# block verbatim and executes it under `sh` with a stub `wget` on PATH that
# records its own argv and snapshots whatever body it was asked to send — so the
# real production code path is exercised, not a reimplementation of it.
#
# Run directly: ./entrypoint_test.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
entrypoint="$script_dir/entrypoint.sh"

fail=0
note() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; fail=1; }

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/entrypoint-test.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

# --- Stub wget: log every argv token, and if invoked with --post-file=FILE,
# snapshot that file's content + mode before returning, so we can inspect what
# was actually about to be sent over the wire without a real network call. ---
stub_bin="$work_dir/bin"
mkdir -p "$stub_bin"

# Test-harness-only shim: on macOS, a bare `mktemp -d` (no template) ignores
# $TMPDIR and resolves to the Darwin per-user temp dir, which this sandboxed
# test runner may not be permitted to write to. Give it an explicit
# $TMPDIR-based template so the *unmodified* entrypoint.sh code under test can
# create its private tmpdir exactly as it does on the real (Linux/BusyBox)
# container, where plain `mktemp -d` already honors $TMPDIR/defaults to /tmp.
# (Built with printf rather than a heredoc: some sandboxed shells disallow the
# temp file bash normally creates internally to expand a heredoc's body.)
mktemp_stub=$'#!/bin/sh\n'
mktemp_stub+=$'real_mktemp="$(command -v /usr/bin/mktemp || command -v /bin/mktemp)"\n'
mktemp_stub+=$'case "$1" in\n'
mktemp_stub+=$'    -d) exec "$real_mktemp" -d "${TMPDIR:-/tmp}/entrypoint-test-inner.XXXXXX" ;;\n'
mktemp_stub+=$'    *) exec "$real_mktemp" "${TMPDIR:-/tmp}/entrypoint-test-inner.XXXXXX" ;;\n'
mktemp_stub+=$'esac\n'
printf '%s' "$mktemp_stub" >"$stub_bin/mktemp"
chmod +x "$stub_bin/mktemp"

argv_log="$work_dir/wget_argv.log"
payload_snapshot="$work_dir/payload_snapshot.json"
payload_path_file="$work_dir/payload_path.txt"
payload_mode_file="$work_dir/payload_mode.txt"
: >"$argv_log"

wget_stub=$'#!/bin/sh\n'
wget_stub+=$'for a in "$@"; do\n'
wget_stub+=$'    printf \'%s\\n\' "$a" >>"$WGET_ARGV_LOG"\n'
wget_stub+=$'    case "$a" in\n'
wget_stub+=$'        --post-file=*)\n'
wget_stub+=$'            f="${a#--post-file=}"\n'
wget_stub+=$'            cp "$f" "$WGET_PAYLOAD_SNAPSHOT"\n'
wget_stub+=$'            printf \'%s\\n\' "$f" >"$WGET_PAYLOAD_PATH_FILE"\n'
wget_stub+=$'            stat -c \'%a\' "$f" >"$WGET_PAYLOAD_MODE_FILE" 2>/dev/null || \\\n'
wget_stub+=$'                stat -f \'%Lp\' "$f" >"$WGET_PAYLOAD_MODE_FILE"\n'
wget_stub+=$'            ;;\n'
wget_stub+=$'    esac\n'
wget_stub+=$'done\n'
wget_stub+=$'exit 0\n'
printf '%s' "$wget_stub" >"$stub_bin/wget"
chmod +x "$stub_bin/wget"

# --- Extract the exact bootstrap block from entrypoint.sh verbatim. ---
# The single-quoted sed pattern intentionally matches the literal text
# '$KEYORIX_ADMIN_PASSWORD' as it appears in entrypoint.sh; it must not expand.
# shellcheck disable=SC2016
block="$(sed -n '/^if \[ -n "\$KEYORIX_ADMIN_PASSWORD" \]; then$/,/^fi$/p' "$entrypoint")"
if [[ -z "$block" ]]; then
    echo "FAIL - could not locate the KEYORIX_ADMIN_PASSWORD bootstrap block in $entrypoint"
    exit 1
fi

password='S3cr3t-Test-P@ssw0rd!'

env -i \
    PATH="$stub_bin:/usr/bin:/bin" \
    TMPDIR="${TMPDIR:-/tmp}" \
    WGET_ARGV_LOG="$argv_log" \
    WGET_PAYLOAD_SNAPSHOT="$payload_snapshot" \
    WGET_PAYLOAD_PATH_FILE="$payload_path_file" \
    WGET_PAYLOAD_MODE_FILE="$payload_mode_file" \
    KEYORIX_ADMIN_PASSWORD="$password" \
    KEYORIX_ADMIN_USERNAME="admin" \
    KEYORIX_ADMIN_EMAIL="admin@example.test" \
    sh -c "$block"

# --- The password must never appear in wget's own argv. ---
if grep -qF -- "$password" "$argv_log"; then
    bad "admin password found in wget argv (this is the #241 leak)"
else
    note "admin password absent from wget argv"
fi

# --- ...but it must still reach the request body, via the --post-file. ---
if [[ ! -s "$payload_snapshot" ]]; then
    bad "wget was never invoked with --post-file; bootstrap payload was not captured"
elif grep -qF -- "$password" "$payload_snapshot"; then
    note "admin password present in the POST body sent via --post-file"
else
    bad "admin password missing from the captured POST body"
fi

if grep -q '"username":"admin"' "$payload_snapshot" && \
   grep -q '"email":"admin@example.test"' "$payload_snapshot"; then
    note "username/email still populated correctly in the POST body"
else
    bad "username/email missing or malformed in the POST body"
fi

# --- The payload file must have been private (owner-only) while it existed. ---
if [[ -f "$payload_mode_file" ]]; then
    mode="$(cat "$payload_mode_file")"
    if [[ "$mode" = "600" ]]; then
        note "payload temp file was created with mode 0600"
    else
        bad "payload temp file mode was '$mode', expected 600"
    fi
fi

# --- The temp file (and its containing dir) must be cleaned up afterwards. ---
if [[ -f "$payload_path_file" ]]; then
    payload_path="$(cat "$payload_path_file")"
    payload_dir="$(dirname "$payload_path")"
    if [[ -e "$payload_path" ]]; then
        bad "bootstrap payload file was not removed after use: $payload_path"
    else
        note "bootstrap payload file was removed after use"
    fi
    if [[ -e "$payload_dir" ]]; then
        bad "bootstrap temp directory was not removed after use: $payload_dir"
    else
        note "bootstrap temp directory was removed after use"
    fi
fi

if [[ "$fail" -ne 0 ]]; then
    echo
    echo "entrypoint_test.sh: FAILED"
    exit 1
fi

echo
echo "entrypoint_test.sh: all checks passed"
