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
    local binary_name checksums_url expected actual
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$arch" in
      x86_64) arch="amd64" ;;
      aarch64 | arm64) arch="arm64" ;;
    esac
    binary_name="keyorix_${os}_${arch}"
    url="https://github.com/keyorixhq/keyorix/releases/download/${VERSION}/${binary_name}"
    checksums_url="https://github.com/keyorixhq/keyorix/releases/download/${VERSION}/checksums.txt"
    echo "Downloading keyorix ${VERSION} (${os}/${arch})..."
    curl -fsSL "$url" -o /tmp/keyorix

    # Verify SHA-256 against the release's published checksums.txt, same
    # approach install.sh uses for the "latest" path below — fail closed
    # (rather than install.sh's skip-if-missing) since this path has no
    # other integrity signal.
    echo "Verifying checksum..."
    expected="$(curl -fsSL "$checksums_url" | awk -v n="$binary_name" '$2==n {print $1}')"
    if [ -z "$expected" ]; then
      echo "error: no checksum published for ${binary_name} at ${VERSION}; refusing to install unverified binary" >&2
      rm -f /tmp/keyorix
      exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum /tmp/keyorix | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      actual="$(shasum -a 256 /tmp/keyorix | awk '{print $1}')"
    else
      echo "error: no sha256sum/shasum tool found; cannot verify checksum" >&2
      rm -f /tmp/keyorix
      exit 1
    fi
    if [ "$actual" != "$expected" ]; then
      echo "error: checksum mismatch for ${binary_name}: expected ${expected}, got ${actual}. Aborting." >&2
      rm -f /tmp/keyorix
      exit 1
    fi
    echo "Checksum verified"

    chmod +x /tmp/keyorix
    if [ -w "$install_dir" ]; then
      mv /tmp/keyorix "${install_dir}/keyorix"
    else
      sudo mv /tmp/keyorix "${install_dir}/keyorix"
    fi
  else
    # Latest release via the official installer (verifies the checksum).
    # Pinned to a specific commit SHA (not the mutable `main` branch, and
    # not a movable tag ref) so a future main-branch or tag compromise
    # can't alter the code piped into `sh` here. Bump deliberately when
    # install.sh's logic needs to change.
    curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/6dd9e555125500e76b4e2035a867621e416585a3/install.sh | sh
  fi
  keyorix --version
}

# validate_secret_name checks that a Keyorix secret NAME is safe to write verbatim
# into $GITHUB_ENV. Keyorix only validates secret name LENGTH server-side (min=1,
# max=255) with no charset restriction, so a principal holding only project-scoped
# secrets.write could name a secret e.g. "FOO\nGITHUB_TOKEN=<attacker-value>\nBAR".
# $GITHUB_ENV is a plain line-based text format the runner parses after this action
# exits; an embedded newline (or other metacharacter) in the "name" field lets that
# single entry masquerade as an extra NAME=VALUE assignment line, overriding env vars
# trusted by later, more-privileged steps in the same job (#174). Requiring a plain
# identifier closes this off entirely: no newline, `=`, or other special character
# can ever reach the file.
validate_secret_name() {
  [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
}

# mask_value registers a GitHub Actions log mask for every line of a (possibly
# multi-line) secret value. `::add-mask::` operates per-LINE: one directive
# redacts exactly one line-oriented string, so a multi-line secret (e.g. a PEM
# private key or a multi-line config blob) previously only had its FIRST line
# masked — every subsequent line of the same secret would still appear in
# plaintext in the job log (#466). Emit a mask for each line individually so
# the whole value is covered no matter how many lines it spans.
mask_value() {
  local val="$1" line
  while IFS= read -r line; do
    [ -n "$line" ] && echo "::add-mask::$line"
  done <<<"$val"
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
    # Reject any secret name that isn't a safe identifier BEFORE it ever reaches
    # $GITHUB_ENV — see validate_secret_name above (#174).
    if ! validate_secret_name "$key"; then
      echo "error: secret name '${key}' is not a valid identifier (must match ^[A-Za-z_][A-Za-z0-9_]*\$) — refusing to export it to \$GITHUB_ENV" >&2
      exit 1
    fi
    val="$(printf '%s' "$json" | jq -r --arg k "$key" '.[$k]')"
    # Mask the value everywhere it might appear in the logs, one line at a
    # time so multi-line secrets are fully covered (#466).
    mask_value "$val"
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

# Only run the action's main flow when this script is executed directly, not when
# it's sourced (e.g. by a test harness that wants validate_secret_name/inject_env
# without performing a real CLI install + secret export).
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  install_cli

  if [ "$EXPORT_TO_ENV" = "true" ]; then
    inject_env
  fi

  if [ -n "$OUTPUT_FILE" ]; then
    # Mask every secret value before writing the dotenv file. This must happen
    # independently of inject_env's masking above, since inject_env (and its
    # ::add-mask:: calls) is skipped entirely when export-to-env=false, which
    # is a documented, supported combination with output-file — without this,
    # a later step that cats/sources the file would print secrets in the clear.
    output_json="$(keyorix secret export --project "$PROJECT" --env "$ENVIRONMENT" --format json)"
    if ! printf '%s' "$output_json" | jq empty 2>/dev/null; then
      echo "error: 'keyorix secret export' did not return valid JSON" >&2
      exit 1
    fi
    while IFS= read -r output_key; do
      [ -n "$output_key" ] || continue
      output_val="$(printf '%s' "$output_json" | jq -r --arg k "$output_key" '.[$k]')"
      mask_value "$output_val"
    done < <(printf '%s' "$output_json" | jq -r 'keys[]')

    # Reuse the CLI's dotenv writer (handles quoting) for the file form.
    keyorix secret export --project "$PROJECT" --env "$ENVIRONMENT" --format dotenv --output "$OUTPUT_FILE"
    echo "Wrote secrets to ${OUTPUT_FILE}"
  fi
fi
