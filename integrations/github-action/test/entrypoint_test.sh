#!/usr/bin/env bash
# Minimal black-box tests for entrypoint.sh, covering fixes across rounds
# (HARDENING-BACKLOG #175/#176/#177, #179, #466):
#
#   #175 — a pinned `version` install must abort if the downloaded binary's
#          checksum doesn't match the release's published checksums.txt.
#   #176 — the "latest" installer path must not fetch install.sh from the
#          mutable `main` branch; it must be pinned to an immutable ref.
#   #177 — secret values must be `::add-mask::`d on the output-file path
#          even when export-to-env=false (so inject_env's masking is
#          skipped).
#   #179 — (1) the action's own KEYORIX_TOKEN must be `::add-mask::`d, not
#          just secret VALUES fetched by it; (2) a `keyorix` already on PATH
#          must never be trusted without a matching checksum, and the CLI
#          download path must not use the fixed, guessable /tmp/keyorix;
#          (3) the $GITHUB_ENV heredoc delimiter must come from a CSPRNG, not
#          the low-entropy $RANDOM.
#   #466 — a multi-line secret value (e.g. a private key) must have EVERY
#          line masked, not just the first — GitHub Actions' ::add-mask::
#          operates per-line.
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

# --- #179 (item 2, static): the CLI download path must no longer be the
# fixed, guessable /tmp/keyorix — it must use a fresh, non-predictable
# mktemp'd directory instead, closing the "guess the path and race a
# substitution" angle.
if grep -q '/tmp/keyorix' "$entrypoint"; then
  bad "#179: install_cli still downloads to the fixed, guessable /tmp/keyorix"
else
  ok "#179: install_cli no longer uses the fixed /tmp/keyorix path"
fi

if grep -q 'mktemp -d' "$entrypoint"; then
  ok "#179: install_cli downloads into a fresh mktemp'd directory"
else
  bad "#179: install_cli does not use mktemp -d for its download directory"
fi

# --- #179 (item 3, static): the $GITHUB_ENV heredoc delimiter must no
# longer be built from the low-entropy (~30-bit) $RANDOM, and must instead
# come from a CSPRNG.
# The literal, unexpanded '${RANDOM}${RANDOM}' text is the point of this case.
# shellcheck disable=SC2016
if grep -q '${RANDOM}${RANDOM}' "$entrypoint"; then
  bad "#179: heredoc delimiter still uses the low-entropy \$RANDOM\$RANDOM"
else
  ok "#179: heredoc delimiter no longer uses \$RANDOM\$RANDOM"
fi

if grep -qE 'openssl rand|/dev/urandom' "$entrypoint"; then
  ok "#179: heredoc delimiter is derived from a CSPRNG (openssl rand/\`/dev/urandom\`)"
else
  bad "#179: heredoc delimiter does not appear to use a CSPRNG"
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

if [[ "$rc1" -ne 0 ]] && grep -qi "checksum mismatch" "${workdir}/stderr1.log"; then
  ok "#175: checksum mismatch aborts the pinned-version install"
else
  bad "#175: checksum mismatch did not abort as expected (rc=${rc1}); stderr: $(cat "${workdir}/stderr1.log")"
fi

# --- #179 (item 2, dynamic): a `keyorix` already on PATH whose checksum
# does NOT match the pinned version's published checksums.txt must be
# ignored (with a warning), not silently trusted — install_cli must fall
# through to a real (verified) download attempt instead.
cp "${fixtures}/mock_keyorix.sh" "${mockbin}/keyorix"
chmod +x "${mockbin}/keyorix"

set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_VERSION="v9.9.9" \
  INPUT_EXPORT_TO_ENV="false" \
  bash "$entrypoint" >"${workdir}/stdout1b.log" 2>"${workdir}/stderr1b.log"
rc1b=$?
set -e

if [[ "$rc1b" -ne 0 ]] \
  && grep -qi "does not match .* published checksum" "${workdir}/stderr1b.log" \
  && grep -qi "checksum mismatch" "${workdir}/stderr1b.log"; then
  ok "#179: an on-PATH keyorix with a mismatched checksum is not silently trusted"
else
  bad "#179: an on-PATH keyorix with a mismatched checksum was not rejected as expected (rc=${rc1b}); stderr: $(cat "${workdir}/stderr1b.log")"
fi

# --- #177: secret values must be masked on the output-file path even
# when export-to-env=false skips inject_env (and its masking) entirely.
#
# Pairs INPUT_VERSION with mock_curl_checksum_match.sh (which serves the
# mock keyorix fixture's own SHA-256 as the "published" checksum) so
# install_cli's checksum-verified reuse path (#179) accepts the already-
# on-PATH mock without any network access — mock_curl_checksum_match.sh
# itself fails the test if a download is attempted instead of a reuse.
cp "${fixtures}/mock_curl_checksum_match.sh" "${mockbin}/curl"
chmod +x "${mockbin}/curl"

out_file="${workdir}/out.env"
set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_VERSION="v1.2.3" \
  MOCK_KEYORIX_PATH="${mockbin}/keyorix" \
  INPUT_EXPORT_TO_ENV="false" \
  INPUT_OUTPUT_FILE="$out_file" \
  bash "$entrypoint" >"${workdir}/stdout2.log" 2>"${workdir}/stderr2.log"
rc2=$?
set -e

if [[ "$rc2" -eq 0 ]] && grep -q "::add-mask::topsecretvalue123" "${workdir}/stdout2.log"; then
  ok "#177: output-file path masks secret values even with export-to-env=false"
else
  bad "#177: output-file path did not mask secret values as expected (rc=${rc2}); stdout: $(cat "${workdir}/stdout2.log"); stderr: $(cat "${workdir}/stderr2.log")"
fi

if [[ -f "$out_file" ]] && grep -q "SUPER_SECRET=topsecretvalue123" "$out_file"; then
  ok "#177: output file was still written with the secret"
else
  bad "#177: output file was not written as expected"
fi

# --- #179 (item 1): the action's own KEYORIX_TOKEN must be masked, not
# just the secret VALUES it fetches — checked against the same run as #177
# above, since KEYORIX_TOKEN is masked unconditionally near the top of the
# script, before install_cli/inject_env even run.
if grep -q "::add-mask::dummy-token" "${workdir}/stdout2.log"; then
  ok "#179: the action's own KEYORIX_TOKEN is masked"
else
  bad "#179: KEYORIX_TOKEN was not masked; stdout: $(cat "${workdir}/stdout2.log")"
fi

# --- #466: a multi-line secret value must have EVERY line masked, not just
# the first. ::add-mask:: registers exactly one line-oriented string per
# call, so a naive single `::add-mask::$val` on a value containing embedded
# newlines only redacts its first line in the job log.
cp "${fixtures}/mock_keyorix_multiline.sh" "${mockbin}/keyorix"
chmod +x "${mockbin}/keyorix"

github_env="${workdir}/github_env"
set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_VERSION="v1.2.3" \
  MOCK_KEYORIX_PATH="${mockbin}/keyorix" \
  INPUT_EXPORT_TO_ENV="true" \
  GITHUB_ENV="$github_env" \
  bash "$entrypoint" >"${workdir}/stdout3.log" 2>"${workdir}/stderr3.log"
rc3=$?
set -e

if [[ "$rc3" -eq 0 ]] \
  && grep -q "::add-mask::line-one-secret" "${workdir}/stdout3.log" \
  && grep -q "::add-mask::line-two-secret" "${workdir}/stdout3.log" \
  && grep -q "::add-mask::line-three-secret" "${workdir}/stdout3.log"; then
  ok "#466: every line of a multi-line secret is masked"
else
  bad "#466: multi-line secret was not fully masked (rc=${rc3}); stdout: $(cat "${workdir}/stdout3.log")"
fi

# --- #179 (item 3, dynamic): the heredoc delimiter written to $GITHUB_ENV
# must carry meaningfully more entropy than the old $RANDOM-based one (two
# $RANDOM draws yield at most a 10-digit decimal string; a 16-byte
# CSPRNG value hex-encodes to 32 hex characters).
delim_line="$(grep -o 'KEYORIX_EOF_[0-9a-f]*' "$github_env" | head -1)"
delim_suffix="${delim_line#KEYORIX_EOF_}"
if [[ "${#delim_suffix}" -ge 32 ]]; then
  ok "#179: heredoc delimiter has >=32 hex characters of entropy (got ${#delim_suffix})"
else
  bad "#179: heredoc delimiter entropy looks too low (delimiter: '${delim_line}', suffix length: ${#delim_suffix})"
fi

echo
echo "${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
