#!/usr/bin/env bash
# entrypoint.sh — install the Keyorix CLI (if needed), then export the requested
# project/environment's secrets and inject them into the GitHub Actions
# environment as MASKED variables (and optionally to a dotenv file).
#
# Reads its config from the INPUT_* / KEYORIX_* env the action.yml sets. Uses
# `keyorix secret export --format json` (pure JSON on stdout; warnings go to
# stderr) so values are parsed unambiguously with jq.
set -euo pipefail

: "${KEYORIX_SERVER:?server input is required}"
: "${KEYORIX_TOKEN:?token input is required}"
export KEYORIX_SERVER KEYORIX_TOKEN

PROJECT="${INPUT_PROJECT:-default}"
ENVIRONMENT="${INPUT_ENVIRONMENT:-development}"
VERSION="${INPUT_VERSION:-}"
EXPORT_TO_ENV="${INPUT_EXPORT_TO_ENV:-true}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-}"

install_dir="/usr/local/bin"

install_cli() {
  if command -v keyorix >/dev/null 2>&1; then
    echo "Using existing keyorix: $(keyorix --version)"
    return
  fi
  if [ -n "$VERSION" ]; then
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$arch" in
      x86_64) arch="amd64" ;;
      aarch64 | arm64) arch="arm64" ;;
    esac
    url="https://github.com/keyorixhq/keyorix/releases/download/${VERSION}/keyorix_${os}_${arch}"
    echo "Downloading keyorix ${VERSION} (${os}/${arch})..."
    curl -fsSL "$url" -o /tmp/keyorix
    chmod +x /tmp/keyorix
    if [ -w "$install_dir" ]; then
      mv /tmp/keyorix "${install_dir}/keyorix"
    else
      sudo mv /tmp/keyorix "${install_dir}/keyorix"
    fi
  else
    # Latest release via the official installer (verifies the checksum).
    curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
  fi
  keyorix --version
}

inject_env() {
  local json key val delim count
  json="$(keyorix secret export --project "$PROJECT" --env "$ENVIRONMENT" --format json)"
  if ! printf '%s' "$json" | jq empty 2>/dev/null; then
    echo "error: 'keyorix secret export' did not return valid JSON" >&2
    exit 1
  fi

  # `keys[]` is newline-delimited; read line-by-line so the loop is whitespace-safe.
  count=0
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    val="$(printf '%s' "$json" | jq -r --arg k "$key" '.[$k]')"
    # Mask the value everywhere it might appear in the logs.
    echo "::add-mask::$val"
    if [ "$EXPORT_TO_ENV" = "true" ]; then
      # Heredoc form so multi-line values survive the GITHUB_ENV file format.
      delim="KEYORIX_EOF_${RANDOM}${RANDOM}"
      {
        printf '%s<<%s\n' "$key" "$delim"
        printf '%s\n' "$val"
        printf '%s\n' "$delim"
      } >>"$GITHUB_ENV"
    fi
    count=$((count + 1))
  done < <(printf '%s' "$json" | jq -r 'keys[]')

  echo "Loaded ${count} secret(s) from project '${PROJECT}' environment '${ENVIRONMENT}'."
}

install_cli

if [ "$EXPORT_TO_ENV" = "true" ]; then
  inject_env
fi

if [ -n "$OUTPUT_FILE" ]; then
  # Reuse the CLI's dotenv writer (handles quoting) for the file form.
  keyorix secret export --project "$PROJECT" --env "$ENVIRONMENT" --format dotenv --output "$OUTPUT_FILE"
  echo "Wrote secrets to ${OUTPUT_FILE}"
fi
