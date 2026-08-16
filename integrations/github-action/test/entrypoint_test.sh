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
  local msg="$1"
  pass=$((pass + 1))
  echo "ok - $msg"
}

bad() {
  local msg="$1"
  fail=$((fail + 1))
  echo "not ok - $msg"
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

# --- adversarial-review (integrations-github-action.json#0): being pinned to
# SOME commit SHA (#176 above) isn't enough on its own — the pin must not
# point at a pre-fix commit. 6dd9e555125500e76b4e2035a867621e416585a3 predates
# b8f79619 (#1342), which closed install.sh's own fail-OPEN checksum gap (a
# missing checksums.txt entry for the platform, or no sha256sum/shasum tool,
# used to log a warning and install anyway). Staying on the stale pin meant
# this default ("latest") install path kept fetching that vulnerable
# install.sh regardless of what HEAD's own copy already fixed. Block-list the
# specific known-vulnerable SHA so a future revert/rebase can't silently
# reintroduce it.
if grep -q '6dd9e555125500e76b4e2035a867621e416585a3' "$entrypoint"; then
  bad "installer is pinned to a pre-#1342 commit with install.sh's fail-open checksum gap"
else
  ok "installer is not pinned to the known-vulnerable pre-#1342 commit"
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

# --- adversarial-review (integrations-github-action.json#2): a secret
# VALUE containing $(...) or `...` command substitution must NOT execute if
# the generated output file is later `source`d by a shell — a real,
# documented consumption pattern for this exact file (see docs/CI_CD.md's
# GitLab/CircleCI examples: `set -a && . ./keyorix.env && set +a`).
# write_output_file used to double-quote such values, which does not
# suppress $(...)/backtick expansion, so `source`ing the file would have
# executed the embedded command.
cp "${fixtures}/mock_keyorix_injection.sh" "${mockbin}/keyorix"
chmod +x "${mockbin}/keyorix"

injection_canary="${workdir}/injection_canary"
backtick_canary="${workdir}/backtick_canary"
out_file_inj="${workdir}/injection.env"
set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_VERSION="v1.2.3" \
  MOCK_KEYORIX_PATH="${mockbin}/keyorix" \
  INJECTION_CANARY="$injection_canary" \
  BACKTICK_CANARY="$backtick_canary" \
  INPUT_EXPORT_TO_ENV="false" \
  INPUT_OUTPUT_FILE="$out_file_inj" \
  bash "$entrypoint" >"${workdir}/stdout4.log" 2>"${workdir}/stderr4.log"
rc4=$?
set -e

if [[ "$rc4" -eq 0 ]] && [[ -f "$out_file_inj" ]]; then
  ok "#2: entrypoint completed successfully and wrote the injection-payload output file"
else
  bad "#2: entrypoint did not complete successfully for the injection case (rc=${rc4}); stderr: $(cat "${workdir}/stderr4.log")"
fi

# The payloads must be SINGLE-quoted in the output file (the fix), not
# double-quoted or left unquoted, so $(...)/backticks inside them can never
# be evaluated by a later `source`.
if grep -qF "INJECTION_SECRET='\$(touch ${injection_canary})'" "$out_file_inj" \
  && grep -qF "BACKTICK_SECRET='\`touch ${backtick_canary}\`'" "$out_file_inj"; then
  ok "#2: command-substitution and backtick payloads are single-quoted (not double-quoted/unquoted) in the output file"
else
  bad "#2: output file did not single-quote the injection payloads as expected: $(cat "$out_file_inj")"
fi

# The actual proof: sourcing the generated file (the documented consumption
# pattern) must NOT execute either embedded command.
# shellcheck disable=SC1090
( set +u; set -a; . "$out_file_inj"; set +a ) || true
if [[ -f "$injection_canary" || -f "$backtick_canary" ]]; then
  bad "#2: sourcing the output file executed an embedded \$(...)/backtick command (a canary file was created)"
else
  ok "#2: sourcing the output file did NOT execute either embedded \$(...)/backtick command"
fi

# --- adversarial-review (integrations-github-action.json#3): install_cli's
# on-PATH-reuse branch checksum-verifies an on-PATH `keyorix` ONCE and must
# not go on to trust/re-execute that same shared PATH location for a LATER
# invocation without re-verification. Simulates an attacker with write
# access to the shared PATH location swapping the binary immediately after
# the checksum check passes but before the later `secret export` call —
# the fix must make that later call unaffected (an already-verified private
# copy), not re-resolve/re-read the now-swapped shared path.
cp "${fixtures}/mock_keyorix_toctou.sh" "${mockbin}/keyorix"
chmod +x "${mockbin}/keyorix"

toctou_canary="${workdir}/toctou_canary"
toctou_github_env="${workdir}/toctou_github_env"

set +e
PATH="${mockbin}:${PATH}" \
  KEYORIX_SERVER="https://example.invalid" \
  KEYORIX_TOKEN="dummy-token" \
  INPUT_VERSION="v1.2.3" \
  MOCK_KEYORIX_PATH="${mockbin}/keyorix" \
  TOCTOU_CANARY="$toctou_canary" \
  INPUT_EXPORT_TO_ENV="true" \
  GITHUB_ENV="$toctou_github_env" \
  bash "$entrypoint" >"${workdir}/stdout5.log" 2>"${workdir}/stderr5.log"
rc5=$?
set -e

if [[ "$rc5" -eq 0 ]] && [[ ! -f "$toctou_canary" ]]; then
  ok "#3: TOCTOU — the later \$KEYORIX_BIN invocation was unaffected by swapping the on-PATH binary after the checksum check (a private copy was used)"
else
  bad "#3: TOCTOU — swapping the on-PATH binary after the checksum check affected a later \$KEYORIX_BIN invocation (rc=${rc5}, canary present: $([[ -f "$toctou_canary" ]] && echo yes || echo no)); stdout: $(cat "${workdir}/stdout5.log"); stderr: $(cat "${workdir}/stderr5.log")"
fi

if grep -q "copied to a private location" "${workdir}/stdout5.log"; then
  ok "#3: install_cli logged that the verified on-PATH binary was copied to a private location before reuse"
else
  bad "#3: install_cli did not log the private-copy behavior the TOCTOU fix relies on; stdout: $(cat "${workdir}/stdout5.log")"
fi

echo
echo "${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
