#!/usr/bin/env bash
# entrypoint_test.sh — minimal regression test for entrypoint.sh's secret-name
# validation (#174: attacker-controllable secret NAMES written unsanitized into
# $GITHUB_ENV could inject a bogus extra NAME=VALUE assignment line, overriding env
# vars trusted by later, more-privileged steps in the same job).
#
# Run directly: ./entrypoint_test.sh
#
# Sources entrypoint.sh to get access to validate_secret_name without performing a
# real CLI install or secret export — entrypoint.sh only runs its top-level
# install/export flow when executed directly (see the BASH_SOURCE guard at the
# bottom of that file), so sourcing it here is side-effect-free.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Satisfy entrypoint.sh's required-input checks (`: "${KEYORIX_SERVER:?...}"` etc.)
# before sourcing; these values are never used since we don't invoke install_cli or
# inject_env, only validate_secret_name directly.
KEYORIX_SERVER="https://example.invalid"
KEYORIX_TOKEN="test-token"
export KEYORIX_SERVER KEYORIX_TOKEN

# shellcheck source=entrypoint.sh disable=SC1091
source "${script_dir}/entrypoint.sh"

fail=0

assert_valid() {
  local name="$1"
  if validate_secret_name "$name"; then
    echo "ok   - accepted: '$name'"
  else
    echo "FAIL - should have been accepted: '$name'"
    fail=1
  fi
}

assert_invalid() {
  local name="$1"
  if validate_secret_name "$name"; then
    echo "FAIL - should have been rejected: '$name'"
    fail=1
  else
    echo "ok   - rejected: '$name'"
  fi
}

# --- Legitimate identifiers must be accepted. ---
assert_valid "STRIPE_KEY"
assert_valid "_LEADING_UNDERSCORE"
assert_valid "A"
assert_valid "MixedCase123"

# --- The #174 exploit primitive: a secret name embedding a newline, crafted to
# look like a second $GITHUB_ENV assignment line once written out verbatim. ---
assert_invalid "$(printf 'FOO\nGITHUB_TOKEN=evil\nBAR')"

# --- Other unsafe characters that must never reach $GITHUB_ENV unsanitized. ---
assert_invalid "FOO=BAR"
assert_invalid "FOO BAR"
assert_invalid "1LEADING_DIGIT"
assert_invalid ""
assert_invalid "FOO<<EOF"
# The literal, unexpanded '$(...)' text is the point of this case.
# shellcheck disable=SC2016
assert_invalid 'FOO$(whoami)'

# --- A secret NAME that's a valid identifier but collides with a reserved,
# security-sensitive env var (PATH substitution, LD_PRELOAD/BASH_ENV code
# execution in a later, more-privileged step, etc.) must still be rejected —
# the charset check above says nothing about the identifier being one of
# these. Checked case-insensitively. ---
assert_invalid "PATH"
assert_invalid "LD_PRELOAD"
assert_invalid "LD_LIBRARY_PATH"
assert_invalid "BASH_ENV"
assert_invalid "bash_env"
assert_invalid "NODE_OPTIONS"
assert_invalid "PYTHONPATH"
assert_invalid "PYTHONSTARTUP"
assert_invalid "PERL5LIB"
assert_invalid "RUBYOPT"
assert_invalid "GEM_PATH"
assert_invalid "NODE_PATH"
assert_invalid "IFS"
assert_invalid "ENV"
assert_invalid "SHELLOPTS"
assert_invalid "PS4"
# #G39: dynamic-linker/interpreter-hook names the denylist was still missing.
assert_invalid "DYLD_INSERT_LIBRARIES"
assert_invalid "PERL5OPT"
assert_invalid "GIT_SSH_COMMAND"
# #G39: CI-credential env vars — the runner's OWN ambient job credentials, a
# DIFFERENT hazard class from the shell/interpreter hooks above (credential
# confusion, not code execution), but a project-scoped secrets.write
# principal has no more business overwriting these than PATH/BASH_ENV.
assert_invalid "GITHUB_TOKEN"
assert_invalid "github_token"
assert_invalid "ACTIONS_RUNTIME_TOKEN"
assert_invalid "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
assert_invalid "ACTIONS_ID_TOKEN_REQUEST_URL"
assert_invalid "ACTIONS_RUNTIME_URL"
assert_invalid "ACTIONS_CACHE_URL"
# A denylisted name as a substring, not an exact match, must still be
# accepted — only the exact reserved name is unsafe.
assert_valid "PATH_TO_CONFIG"
assert_valid "MY_BASH_ENV_VAR"
assert_valid "GITHUB_TOKEN_BACKUP"

if [[ "$fail" -ne 0 ]]; then
  echo
  echo "entrypoint_test.sh: FAILED"
  exit 1
fi

echo
echo "entrypoint_test.sh: all checks passed"
