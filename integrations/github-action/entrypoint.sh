#!/usr/bin/env bash
# entrypoint.sh — install the Keyorix CLI (if needed), then export the requested
# project/environment's secrets and inject them into the GitHub Actions
# environment as MASKED variables (and optionally to a dotenv file).
#
# Reads its config from the INPUT_* / KEYORIX_* env the action.yml sets. Uses
# `keyorix secret export --format json` (pure JSON on stdout; warnings go to
# stderr) so values are parsed unambiguously with jq.
set -euo pipefail

# mask_value registers a GitHub Actions log mask for every line of a (possibly
# multi-line) secret value. `::add-mask::` operates per-LINE: one directive
# redacts exactly one line-oriented string, so a multi-line secret (e.g. a PEM
# private key or a multi-line config blob) previously only had its FIRST line
# masked — every subsequent line of the same secret would still appear in
# plaintext in the job log (#466). Emit a mask for each line individually so
# the whole value is covered no matter how many lines it spans.
#
# Defined this early (rather than alongside inject_env below) so it's
# available immediately after KEYORIX_TOKEN is read, for #179 below.
mask_value() {
  local val="$1" line
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "::add-mask::$line"
  done < <(printf '%s\n' "$val")
}

: "${KEYORIX_SERVER:?server input is required}"
: "${KEYORIX_TOKEN:?token input is required}"
export KEYORIX_SERVER KEYORIX_TOKEN

# Mask the action's own auth token as early as possible (#179). Unlike the
# SECRET VALUES this action fetches (masked individually by mask_value/
# inject_env below), KEYORIX_TOKEN itself was never masked — if it were ever
# echoed by an error message or debug trace (this script's own, the CLI's, or
# a later step's), it would render in plaintext in the job log.
mask_value "$KEYORIX_TOKEN"

PROJECT="${INPUT_PROJECT:-default}"
ENVIRONMENT="${INPUT_ENVIRONMENT:-development}"
VERSION="${INPUT_VERSION:-}"
EXPORT_TO_ENV="${INPUT_EXPORT_TO_ENV:-true}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-}"

install_dir="/usr/local/bin"

# sha256_of prints the SHA-256 of the given file using whichever of
# sha256sum/shasum is available, or fails if neither is.
sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    return 1
  fi
}

install_cli() {
  # A `keyorix` binary already on PATH must never be trusted blindly (#179):
  # a compromised runner image, a poisoned PATH, or a self-hosted runner
  # shared with other jobs could otherwise substitute a malicious binary that
  # this action would then execute with the caller's KEYORIX_TOKEN. We only
  # ever reuse such a binary after verifying ITS SHA-256 against the same
  # published checksums.txt used for the download path below — which
  # requires a pinned `version` input. An unpinned "latest" install has no
  # fixed, known-good hash to check an arbitrary on-PATH binary against, so
  # that path (the `else` branch) always fetches and verifies a fresh copy
  # instead of ever considering what's already on PATH.
  if [[ -n "$VERSION" ]]; then
    local os arch binary_name url checksums_url expected actual tmp_dir tmp_bin existing
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$arch" in
      x86_64) arch="amd64" ;;
      aarch64 | arm64) arch="arm64" ;;
      *) ;;
    esac
    binary_name="keyorix_${os}_${arch}"
    url="https://github.com/keyorixhq/keyorix/releases/download/${VERSION}/${binary_name}"
    checksums_url="https://github.com/keyorixhq/keyorix/releases/download/${VERSION}/checksums.txt"

    # Fetch the expected checksum first, fail closed (rather than
    # install.sh's skip-if-missing) since this path has no other integrity
    # signal — this is required whether we end up reusing an existing binary
    # or downloading a fresh one.
    echo "Verifying checksum..."
    expected="$(curl --proto '=https' --tlsv1.2 -fsSL "$checksums_url" | awk -v n="$binary_name" '$2==n {print $1}')" # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; redirect-following is required for GitHub release CDN
    if [[ -z "$expected" ]]; then
      echo "error: no checksum published for ${binary_name} at ${VERSION}; refusing to install unverified binary" >&2
      exit 1
    fi

    existing="$(command -v keyorix 2>/dev/null || true)"
    if [[ -n "$existing" ]]; then
      if actual="$(sha256_of "$existing" 2>/dev/null)" && [[ -n "$actual" ]] && [[ "$actual" = "$expected" ]]; then
        echo "Using existing keyorix at ${existing} (checksum verified against ${VERSION})"
        keyorix --version
        return
      fi
      echo "warning: keyorix already on PATH does not match ${VERSION}'s published checksum; ignoring it and installing a fresh, verified copy" >&2
    fi

    # A fresh, non-predictable directory per run (mirroring install.sh's own
    # `mktemp -d`, not a fixed, guessable path as this used previously)
    # closes off a symlink/TOCTOU race where another process on a shared
    # runner pre-creates or swaps the path between our download, checksum
    # check, chmod, and mv below. Cleaned up on any exit path via the trap.
    #
    # An explicit template under $TMPDIR (rather than a bare `mktemp -d`) so
    # this respects a caller-set $TMPDIR instead of some implementations'
    # fixed OS temp dir fallback.
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/keyorix-cli.XXXXXX")"
    trap 'rm -rf "$tmp_dir"' EXIT
    tmp_bin="${tmp_dir}/keyorix"

    echo "Downloading keyorix ${VERSION} (${os}/${arch})..."
    curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$tmp_bin" # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; redirect-following is required for GitHub release CDN

    if ! actual="$(sha256_of "$tmp_bin")"; then
      echo "error: no sha256sum/shasum tool found; cannot verify checksum" >&2
      exit 1
    fi
    if [[ "$actual" != "$expected" ]]; then
      echo "error: checksum mismatch for ${binary_name}: expected ${expected}, got ${actual}. Aborting." >&2
      exit 1
    fi
    echo "Checksum verified"

    chmod +x "$tmp_bin"
    if [[ -w "$install_dir" ]]; then
      mv "$tmp_bin" "${install_dir}/keyorix"
    else
      sudo mv "$tmp_bin" "${install_dir}/keyorix"
    fi
  else
    # Latest release via the official installer (verifies the checksum, and
    # itself downloads into its own `mktemp -d`). Pinned to a specific commit
    # SHA (not the mutable `main` branch, and not a movable tag ref) so a
    # future main-branch or tag compromise can't alter the code piped into
    # `sh` here. Bump deliberately when install.sh's logic needs to change.
    curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/6dd9e555125500e76b4e2035a867621e416585a3/install.sh | sh # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; commit SHA is pinned not floating
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
  local name="$1"
  [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
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
    [[ -n "$key" ]] || continue
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
    if [[ "$EXPORT_TO_ENV" = "true" ]]; then
      # Heredoc form so multi-line values survive the GITHUB_ENV file format.
      # The delimiter must be unguessable: if it ever collided with (or were
      # predictable enough to be engineered to collide with) a line inside
      # $val, that line would be parsed as the heredoc terminator, truncating
      # the secret and injecting whatever follows as extra $GITHUB_ENV
      # content. `$RANDOM` is a 15-bit (0-32767) LCG PRNG — two draws give
      # only ~30 bits of entropy and are trivially brute-forceable/predictable
      # (#179) — so derive it from a CSPRNG instead, matching install.sh's use
      # of /dev/urandom-backed tooling elsewhere in this repo's shell scripts.
      delim="KEYORIX_EOF_$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
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

  if [[ "$EXPORT_TO_ENV" = "true" ]]; then
    inject_env
  fi

  if [[ -n "$OUTPUT_FILE" ]]; then
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
      [[ -n "$output_key" ]] || continue
      output_val="$(printf '%s' "$output_json" | jq -r --arg k "$output_key" '.[$k]')"
      mask_value "$output_val"
    done < <(printf '%s' "$output_json" | jq -r 'keys[]')

    # Reuse the CLI's dotenv writer (handles quoting) for the file form.
    keyorix secret export --project "$PROJECT" --env "$ENVIRONMENT" --format dotenv --output "$OUTPUT_FILE"
    echo "Wrote secrets to ${OUTPUT_FILE}"
  fi
fi
