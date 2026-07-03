#!/usr/bin/env bash
# Mock keyorix CLI used by entrypoint_test.sh's #466 case: already
# "installed" (so install_cli short-circuits without touching the
# network); returns a secret VALUE that spans multiple lines (simulating,
# e.g., a PEM private key), so the test can verify every line gets its own
# ::add-mask:: directive, not just the first.
if [ "$1" = "--version" ]; then
  echo "keyorix version mock-1.0.0"
  exit 0
fi
if [ "$1" = "secret" ] && [ "$2" = "export" ]; then
  fmt=""
  args=("$@")
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
      --format) fmt="${args[$((i + 1))]}" ;;
    esac
  done
  case "$fmt" in
    json)
      printf '{"MULTI_LINE_SECRET":"line-one-secret\\nline-two-secret\\nline-three-secret"}'
      exit 0
      ;;
  esac
fi
echo "mock keyorix: unhandled args: $*" >&2
exit 1
