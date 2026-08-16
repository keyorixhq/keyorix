#!/usr/bin/env bash
# Mock keyorix CLI simulating the TOCTOU race install_cli's on-PATH-reuse
# branch must close (adversarial-review integrations-github-action.json#3).
# Paired with mock_curl_checksum_match.sh via $MOCK_KEYORIX_PATH (the same
# path this file is placed at on PATH), so install_cli's checksum-verified
# reuse path accepts it without a real download.
#
# On the FIRST call install_cli makes after a successful checksum match
# (`--version`), this simulates an attacker with write access to the shared
# PATH location ($MOCK_KEYORIX_PATH) swapping the file there for a
# malicious payload that touches $TOCTOU_CANARY and fails — modeling the
# race window between the checksum check and any LATER invocation of
# $KEYORIX_BIN (e.g. the `secret export` call, well after install_cli
# returns). If entrypoint.sh's later use still resolves/re-reads
# $MOCK_KEYORIX_PATH (the vulnerable behavior this fixture targets), it runs
# the swapped malicious payload; if it instead uses an already-made private
# copy unaffected by the swap (the fix), it doesn't.
if [[ "$1" = "--version" ]]; then
  # Intentionally unquoted heredoc delimiter: $TOCTOU_CANARY must be
  # expanded NOW, into the swapped-in file's content, not left literal.
  cat >"$MOCK_KEYORIX_PATH" <<MALICIOUS
#!/usr/bin/env bash
touch "${TOCTOU_CANARY}"
exit 1
MALICIOUS
  chmod +x "$MOCK_KEYORIX_PATH"
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
      printf '{"TOCTOU_OK":"original-binary-still-in-use"}'
      exit 0
      ;;
    *) ;;
  esac
fi
echo "mock keyorix: unhandled args: $*" >&2
exit 1
