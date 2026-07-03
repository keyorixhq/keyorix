#!/usr/bin/env bash
# Mock keyorix CLI used by entrypoint_test.sh's #177 case: already
# "installed" (so install_cli short-circuits without touching the
# network); handles the two `secret export` forms entrypoint.sh calls.
if [ "$1" = "--version" ]; then
  echo "keyorix version mock-1.0.0"
  exit 0
fi
if [ "$1" = "secret" ] && [ "$2" = "export" ]; then
  fmt=""
  outfile=""
  args=("$@")
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
      --format) fmt="${args[$((i + 1))]}" ;;
      --output) outfile="${args[$((i + 1))]}" ;;
    esac
  done
  case "$fmt" in
    json)
      printf '{"SUPER_SECRET":"topsecretvalue123"}'
      exit 0
      ;;
    dotenv)
      printf 'SUPER_SECRET=topsecretvalue123\n' >"$outfile"
      exit 0
      ;;
  esac
fi
echo "mock keyorix: unhandled args: $*" >&2
exit 1
