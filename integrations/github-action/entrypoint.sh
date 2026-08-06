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

# KEYORIX_BIN is set by install_cli to the ABSOLUTE path of the checksum-
# verified binary it decided to use (either the existing on-PATH binary,
# once its hash was confirmed to match, or the freshly downloaded/installed
# copy at $install_dir). Every later invocation of the CLI in this script
# MUST go through "$KEYORIX_BIN", never a bare `keyorix` — a bare command
# name re-resolves via $PATH at call time, which can point somewhere else
# entirely than what was just verified (see install_cli's own comment on
# why an on-PATH binary can't be trusted blindly).
KEYORIX_BIN=""

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

    # Fetch the expected checksum first and fail closed if none is published
    # (install.sh does the same for its own download) since this path has no
    # other integrity signal — this is required whether we end up reusing an
    # existing binary or downloading a fresh one.
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
        KEYORIX_BIN="$existing"
        "$KEYORIX_BIN" --version
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
    KEYORIX_BIN="${install_dir}/keyorix"
  else
    # Latest release via the official installer (verifies the checksum, and
    # itself downloads into its own `mktemp -d`). Pinned to a specific commit
    # SHA (not the mutable `main` branch, and not a movable tag ref) so a
    # future main-branch or tag compromise can't alter the code piped into
    # `sh` here. Bump deliberately when install.sh's logic needs to change.
    curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/6dd9e555125500e76b4e2035a867621e416585a3/install.sh | sh # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; commit SHA is pinned not floating
    # install.sh (pinned above) always installs to this same directory.
    KEYORIX_BIN="${install_dir}/keyorix"
  fi
  "$KEYORIX_BIN" --version
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

# DANGEROUS_ENV_NAMES are environment variable names that are safe ASCII
# identifiers (so they pass the charset check above) but are interpreted
# specially by the shell or by interpreters/loaders that a later step in the
# same job is likely to invoke. The identifier check alone only stops
# metacharacter/newline injection into $GITHUB_ENV (#174 above) — it says
# nothing about the NAME itself being one of these. A principal holding only
# project-scoped secrets.write (not job/workflow admin) could name a secret
# e.g. "BASH_ENV" pointing at an attacker-controlled script: inject_env would
# happily write it to $GITHUB_ENV, and every subsequent bash-shell step in
# the same job sources that script before running its own commands — code
# execution in a more-privileged step. PATH lets an attacker substitute
# arbitrary binaries; LD_PRELOAD/LD_LIBRARY_PATH inject native code into any
# process exec'd afterward; the rest are the equivalent hooks for other
# interpreters commonly present in CI runners (Node, Python, Perl, Ruby).
DANGEROUS_ENV_NAMES=(
  PATH LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV IFS SHELLOPTS PS4
  NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONSTARTUP PERL5LIB RUBYOPT GEM_PATH
)

validate_secret_name() {
  local name="$1" upper_name candidate
  [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1

  # Reject denylisted names case-insensitively: GitHub Actions env vars are
  # themselves case-sensitive, but some shells/tools that consult these
  # particular names (e.g. loaders on case-insensitive filesystems, or
  # third-party tooling) aren't reliably consistent about case, so compare
  # uppercased to be safe rather than relying on exact-case matches only.
  # `tr` rather than bash 4's `${name^^}` since macOS ships bash 3.2.
  upper_name="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
  for candidate in "${DANGEROUS_ENV_NAMES[@]}"; do
    [[ "$upper_name" == "$candidate" ]] && return 1
  done

  return 0
}

# fetch_export_json calls `keyorix secret export --format json` (via the
# checksum-verified $KEYORIX_BIN, never a bare `keyorix`) once and validates
# the result is well-formed JSON on stdout. This is the SINGLE source of
# truth for a given run: both inject_env and write_output_file are handed
# the SAME already-fetched JSON rather than each independently calling the
# server, so a secret value that changes between calls (rotation, or any
# concurrent write) can't land in one output but not the other — see
# write_output_file's comment for the concrete failure mode this closes.
fetch_export_json() {
  local json
  json="$("$KEYORIX_BIN" secret export --project "$PROJECT" --env "$ENVIRONMENT" --format json)"
  if ! printf '%s' "$json" | jq empty 2>/dev/null; then
    echo "error: 'keyorix secret export' did not return valid JSON" >&2
    exit 1
  fi
  printf '%s' "$json"
}

inject_env() {
  local json="$1"
  local key val delim count

  # `keys[]` is newline-delimited; read line-by-line so the loop is whitespace-safe.
  count=0
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    # Reject any secret name that isn't a safe identifier, or that collides
    # with a security-sensitive reserved env var, BEFORE it ever reaches
    # $GITHUB_ENV — see validate_secret_name above (#174, and the
    # DANGEROUS_ENV_NAMES denylist).
    if ! validate_secret_name "$key"; then
      echo "error: secret name '${key}' is not safe to export to \$GITHUB_ENV (must match ^[A-Za-z_][A-Za-z0-9_]*\$ and must not be a reserved/security-sensitive env var name such as PATH, LD_PRELOAD, or BASH_ENV) — refusing to export it" >&2
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

# write_output_file masks every secret value (independently of inject_env's
# masking, since inject_env — and its ::add-mask:: calls — is skipped
# entirely when export-to-env=false, a documented, supported combination
# with output-file) and writes a dotenv file, DERIVING its content locally
# from the same already-fetched $json rather than making a second,
# independent `keyorix secret export --format dotenv` call. Two independent
# server round-trips could observe two different snapshots of the secrets
# (rotation, or any concurrent write): masking values read from ONE fetch
# while writing values from a SECOND, different fetch would let a changed
# value land in the file without ever being registered via mask_value, so a
# later step that cats/sources the file would print it in the clear in the
# job log. Quoting mirrors internal/cli/secret/export.go's writeDotenv so
# the file matches what `keyorix secret export --format dotenv` itself
# would have produced from this same data.
write_output_file() {
  local json="$1" file="$2" key val escaped

  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    val="$(printf '%s' "$json" | jq -r --arg k "$key" '.[$k]')"
    mask_value "$val"
  done < <(printf '%s' "$json" | jq -r 'keys[]')

  # Refuse to write through a pre-existing path — including a symlink an
  # attacker with write access to a shared directory planted ahead of time —
  # mirroring internal/cli/secret/export.go's createExportFile (O_EXCL).
  # `noclobber` makes bash's own `>` redirection use O_EXCL, so this fails
  # closed the same way rather than silently following/truncating it.
  if ! (
    set -o noclobber
    {
      printf '# Exported by Keyorix\n'
      while IFS= read -r key; do
        [[ -n "$key" ]] || continue
        val="$(printf '%s' "$json" | jq -r --arg k "$key" '.[$k]')"
        if [[ "$val" == *[[:space:]]* || "$val" == *"\""* || "$val" == *"'"* || "$val" == *"="* || "$val" == *"\\"* ]]; then
          escaped="${val//\\/\\\\}"
          escaped="${escaped//\"/\\\"}"
          printf '%s="%s"\n' "$key" "$escaped"
        else
          printf '%s=%s\n' "$key" "$val"
        fi
      done < <(printf '%s' "$json" | jq -r 'keys[]')
    } >"$file"
  ); then
    echo "error: cannot create output file '${file}' (it may already exist — remove it or choose a different path)" >&2
    exit 1
  fi
}

# Only run the action's main flow when this script is executed directly, not when
# it's sourced (e.g. by a test harness that wants validate_secret_name/inject_env
# without performing a real CLI install + secret export).
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  install_cli

  # Fetch once, share the result — see fetch_export_json's comment.
  secrets_json=""
  if [[ "$EXPORT_TO_ENV" = "true" ]] || [[ -n "$OUTPUT_FILE" ]]; then
    secrets_json="$(fetch_export_json)"
  fi

  if [[ "$EXPORT_TO_ENV" = "true" ]]; then
    inject_env "$secrets_json"
  fi

  if [[ -n "$OUTPUT_FILE" ]]; then
    write_output_file "$secrets_json" "$OUTPUT_FILE"
    echo "Wrote secrets to ${OUTPUT_FILE}"
  fi
fi
