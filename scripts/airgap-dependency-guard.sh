#!/usr/bin/env bash
# airgap-dependency-guard.sh — ADR-109 step 6 (B2/S3): fails if the
# AIR-GAPPED server build (-tags noaws,noazure,nogcp — see `make
# build-server-airgap`) links a package from any of the three excluded cloud
# SDKs. Vault and Kubernetes stay in the air-gapped profile (ADR-109's
# open-questions decision: on-prem Vault read-through and on-prem k8s are
# legitimate air-gapped uses) and are deliberately NOT checked here.
#
# Method: `go list -deps` under the exact tag set the airgap profile builds
# with, filtered against the three SDK import-path prefixes. Anything found
# is checked against ALLOWLIST below — every entry there needs its own
# reason, checked in ($allowlist entries not found in the actual dependency
# set are themselves flagged as stale, so this can't silently drift into an
# allowlist nobody re-reads).
#
# Usage: scripts/airgap-dependency-guard.sh
# Exit 0: clean (no forbidden package outside the allowlist).
# Exit 1: at least one forbidden package found, printed to stderr.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Each entry: "import/path/prefix|reason". Empty today — the airgap profile
# (-tags noaws,noazure,nogcp) currently links ZERO packages from any of the
# three excluded SDKs (measured 2026-09-28, ADR-109 steps 1-5 + step 6 S1/S2
# already landed). Add an entry here ONLY if a future dependency becomes
# genuinely unavoidable, with a reason a reviewer can check.
ALLOWLIST=(
)

FORBIDDEN_PATTERN='(^|/)(github\.com/aws/aws-sdk-go-v2|github\.com/Azure/azure-sdk-for-go|cloud\.google\.com/go)(/|$)'

deps="$(GOWORK=off go -C "$repo_root" list -tags "noaws noazure nogcp" -deps ./server)"

forbidden="$(echo "$deps" | grep -E "$FORBIDDEN_PATTERN" || true)"

allowed_prefixes=()
for entry in "${ALLOWLIST[@]+"${ALLOWLIST[@]}"}"; do
	allowed_prefixes+=("${entry%%|*}")
done

unallowed=()
while IFS= read -r pkg; do
	[ -z "$pkg" ] && continue
	is_allowed=false
	for prefix in "${allowed_prefixes[@]+"${allowed_prefixes[@]}"}"; do
		case "$pkg" in
		"$prefix"*) is_allowed=true ;;
		esac
	done
	if [ "$is_allowed" = false ]; then
		unallowed+=("$pkg")
	fi
done <<<"$forbidden"

if [ "${#unallowed[@]}" -gt 0 ]; then
	echo "airgap-dependency-guard: the air-gapped profile (-tags noaws,noazure,nogcp) links forbidden cloud-SDK package(s):" >&2
	printf '  %s\n' "${unallowed[@]}" >&2
	echo "" >&2
	echo "Each excludes via a no<x> build tag (ADR-109 step 6) — the file pulling this in is missing its !no<x> guard, or a new dependency was added without checking this guard. Add an ALLOWLIST entry (with a reason) only if genuinely unavoidable." >&2
	exit 1
fi

# Stale-allowlist check: every ALLOWLIST entry should actually match
# something in the current dependency set, or it's dead weight nobody would
# notice removing a real exclusion behind.
for entry in "${ALLOWLIST[@]+"${ALLOWLIST[@]}"}"; do
	prefix="${entry%%|*}"
	if ! echo "$deps" | grep -qF "$prefix"; then
		echo "airgap-dependency-guard: ALLOWLIST entry '$prefix' no longer matches any dependency in the air-gapped build — remove it (stale allowlist entries hide the guard becoming stricter than intended)." >&2
		exit 1
	fi
done

echo "airgap-dependency-guard: OK — 0 forbidden cloud-SDK package(s) in the air-gapped server build (${#allowed_prefixes[@]} allowlisted)."
