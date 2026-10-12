#!/usr/bin/env bash
# Installs gosec at $GOSEC_VERSION, but built against golang.org/x/tools
# $GOSEC_TOOLS_VERSION rather than whatever gosec's own go.mod pins.
#
# gosec v2.29.0 (latest as of 2026-10) still links x/tools v0.49.0, whose
# gcimporter only decodes export-data format version <=4. Go 1.27.2
# (GO-2026-6610..6617 fix) writes format version 5, so a plain
# `go install github.com/securego/gosec/v2/cmd/gosec@...` binary type-errors
# on every package ("has type errors, skipping SSA analysis") the moment it
# scans anything built with 1.27.2 -- zero real findings either way, but a
# hard CI failure instead of a clean scan.
#
# A throwaway module that requires both gosec and a newer x/tools lets Go's
# minimum-version-selection pick the newer x/tools for the build (allowed:
# MVS only ever rounds a requirement UP), without needing a gosec release or
# a fork. Re-run this whenever x/tools' own export-data reader falls behind
# the Go toolchain again -- bump GOSEC_TOOLS_VERSION, not this script.
set -euo pipefail

: "${GOSEC_VERSION:?GOSEC_VERSION must be set}"
: "${GOSEC_TOOLS_VERSION:?GOSEC_TOOLS_VERSION must be set}"

dest="${1:?usage: install-gosec.sh <dest-bin-path>}"
dest="$(mkdir -p "$(dirname "$dest")" && cd "$(dirname "$dest")" && pwd)/$(basename "$dest")"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

(
  cd "$workdir"
  go mod init gosec-install >/dev/null
  go get "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
  go get "golang.org/x/tools@${GOSEC_TOOLS_VERSION}"
  go build -o "$dest" github.com/securego/gosec/v2/cmd/gosec
)
