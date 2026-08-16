#!/usr/bin/env bash
# Mock keyorix CLI used by entrypoint_test.sh's adversarial-review
# integrations-github-action.json#2 case: placed on PATH before
# entrypoint.sh runs, paired with INPUT_VERSION and
# mock_curl_checksum_match.sh (which serves this exact file's SHA-256 as the
# published checksum) so install_cli's checksum-verified reuse path accepts
# it without touching the network.
#
# Returns two secret VALUES crafted as command-substitution / backtick
# payloads — `touch $INJECTION_CANARY` and `touch $BACKTICK_CANARY` — so the
# test can prove write_output_file's escaping neutralizes BOTH forms of
# command substitution: if the generated output file is later `source`d and
# either canary file gets created, the payload executed and the fix failed.
if [[ "$1" = "--version" ]]; then
  echo "keyorix version mock-1.0.0"
  exit 0
fi
if [[ "$1" = "secret" ]] && [[ "$2" = "export" ]]; then
  fmt=""
  args=("$@")
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
      --format) fmt="${args[$((i + 1))]}" ;;
      *) ;;
    esac
  done
  case "$fmt" in
    json)
      # The literal, unexpanded $(...) / `...` text is the point of this
      # fixture — it must reach entrypoint.sh's jq parsing unevaluated.
      # shellcheck disable=SC2016
      printf '{"INJECTION_SECRET":"$(touch %s)","BACKTICK_SECRET":"`touch %s`"}' \
        "$INJECTION_CANARY" "$BACKTICK_CANARY"
      exit 0
      ;;
    *) ;;
  esac
fi
echo "mock keyorix: unhandled args: $*" >&2
exit 1
