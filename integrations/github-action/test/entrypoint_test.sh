#!/usr/bin/env bash
# Minimal black-box tests for entrypoint.sh, covering the three fixes in
# this round (HARDENING-BACKLOG #175/#176/#177):
#
#   #175 — a pinned `version` install must abort if the downloaded binary's
#          checksum doesn't match the release's published checksums.txt.
#   #176 — the "latest" installer path must not fetch install.sh from the
#          mutable `main` branch; it must be pinned to an immutable ref.
#   #177 — secret values must be `::add-mask::`d on the output-file path
#          even when export-to-env=false (so inject_env's masking is
#          skipped).
#
# Runs entrypoint.sh as a real subprocess against a mocked PATH (fake
# curl/keyorix, in test/fixtures/), so it exercises the actual script, not
# a reimplementation of it.
#
# Usage: integrations/github-action/test/entrypoint_test.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
entrypoint="${script_dir}/../entrypoint.sh"
fixtures="${script_dir}/fixtures"

pass=0
fail=0

ok() {
  pass=$((pass + 1))
  echo "ok - $1"
}

bad() {
  fail=$((fail + 1))
  echo "not ok - $1"
}

# Use $TMPDIR explicitly (rather than a bare `mktemp -d`) since some
# mktemp implementations fall back to a fixed OS temp dir that ignores
# $TMPDIR, which trips sandboxes that only allow writes under $TMPDIR.
workdir="$(mktemp -d "${TMPDIR:-/tmp}/entrypoint_test.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT
mockbin="${workdir}/bin"
mkdir -p "$mockbin"

# --- #176: static check — the "latest" path must not reference the
# mutable `main` branch, and must be pinned to a 40-char commit SHA.
if grep -q 'raw\.githubusercontent\.com/keyorixhq/keyorix/main/install\.sh' "$entrypoint"; then
  bad "#176: installer still fetches install.sh from the mutable main branch"
else
  ok "#176: installer no longer fetches install.sh from main"
fi

if grep -qE 'raw\.githubusercontent\.com/keyorixhq/keyorix/[0-9a-f]{40}/install\.sh' "$entrypoint"; then
  ok "#176: installer is pinned to an immutable commit SHA"
else
  bad "#176: installer is not pinned to a commit SHA"
fi

# --- #175: a checksum mismatch on the pinned-version path must abort
# loudly, not proceed to install the (corrupted/tampered) binary.
cp "${fixtures}/mock_curl_checksum_mismatch.sh" "${mockbin}/curl"
chmod +x "${mockbin}/curl"

set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_VERSION="v9.9.9" \
  INPUT_EXPORT_TO_ENV="false" \
  bash "$entrypoint" >"${workdir}/stdout1.log" 2>"${workdir}/stderr1.log"
rc1=$?
set -e

if [ "$rc1" -ne 0 ] && grep -qi "checksum mismatch" "${workdir}/stderr1.log"; then
  ok "#175: checksum mismatch aborts the pinned-version install"
else
  bad "#175: checksum mismatch did not abort as expected (rc=${rc1}); stderr: $(cat "${workdir}/stderr1.log")"
fi

# --- #177: secret values must be masked on the output-file path even
# when export-to-env=false skips inject_env (and its masking) entirely.
cp "${fixtures}/mock_keyorix.sh" "${mockbin}/keyorix"
chmod +x "${mockbin}/keyorix"

out_file="${workdir}/out.env"
set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_EXPORT_TO_ENV="false" \
  INPUT_OUTPUT_FILE="$out_file" \
  bash "$entrypoint" >"${workdir}/stdout2.log" 2>"${workdir}/stderr2.log"
rc2=$?
set -e

if [ "$rc2" -eq 0 ] && grep -q "::add-mask::topsecretvalue123" "${workdir}/stdout2.log"; then
  ok "#177: output-file path masks secret values even with export-to-env=false"
else
  bad "#177: output-file path did not mask secret values as expected (rc=${rc2}); stdout: $(cat "${workdir}/stdout2.log"); stderr: $(cat "${workdir}/stderr2.log")"
fi

if [ -f "$out_file" ] && grep -q "SUPER_SECRET=topsecretvalue123" "$out_file"; then
  ok "#177: output file was still written with the secret"
else
  bad "#177: output file was not written as expected"
fi

echo
echo "${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
