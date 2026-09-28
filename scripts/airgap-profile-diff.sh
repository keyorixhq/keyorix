#!/usr/bin/env bash
# airgap-profile-diff.sh — ADR-109 step 6 (B4/S5): prints a full-vs-air-gapped
# dependency-count and SBOM-component-count diff as a GitHub-flavored markdown
# table, for release-dry-run.yml's job summary. Callable standalone too (just
# prints to stdout).
#
# Usage: scripts/airgap-profile-diff.sh [<full-sbom.cdx.json> <airgap-sbom.cdx.json>]
# The two SBOM args are optional — pass them when `make release`/`make sbom`
# already produced dist/keyorix-server_linux_amd64_sbom.cdx.json and
# dist/keyorix-server-airgap_linux_amd64_sbom.cdx.json in this run (skips the
# SBOM component-count rows, printing "n/a", if omitted or the files don't
# exist — this script never re-generates them itself, that's `make release`'s
# job, not this one's).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

full_sbom="${1:-}"
airgap_sbom="${2:-}"

CLOUD_PATTERN='(^|/)(github\.com/aws/aws-sdk-go-v2|github\.com/Azure/azure-sdk-for-go|cloud\.google\.com/go)(/|$)'

full_deps="$(GOWORK=off go -C "$repo_root" list -deps ./server)"
airgap_deps="$(GOWORK=off go -C "$repo_root" list -tags "noaws noazure nogcp" -deps ./server)"

full_total="$(echo "$full_deps" | wc -l | tr -d ' ')"
airgap_total="$(echo "$airgap_deps" | wc -l | tr -d ' ')"
full_cloud="$(echo "$full_deps" | grep -cE "$CLOUD_PATTERN" || true)"
airgap_cloud="$(echo "$airgap_deps" | grep -cE "$CLOUD_PATTERN" || true)"

sbom_component_count() {
	local f="$1"
	if [ -n "$f" ] && [ -f "$f" ]; then
		if command -v jq >/dev/null 2>&1; then
			jq '.components | length' "$f"
		else
			echo "n/a (jq not available)"
		fi
	else
		echo "n/a (not generated this run)"
	fi
}

full_sbom_count="$(sbom_component_count "$full_sbom")"
airgap_sbom_count="$(sbom_component_count "$airgap_sbom")"

cat <<EOF
### ADR-109 step 6: full vs air-gapped server profile

| Metric | full | air-gapped (noaws,noazure,nogcp) |
|---|---|---|
| \`go list -deps ./server\`, total packages | ${full_total} | ${airgap_total} |
| ...of which aws-sdk-go-v2/azure-sdk-for-go/cloud.google.com | ${full_cloud} | ${airgap_cloud} |
| SBOM component count (linux/amd64) | ${full_sbom_count} | ${airgap_sbom_count} |

Vault and Kubernetes intentionally stay in the air-gapped profile (ADR-109's
open-questions decision: on-prem Vault read-through and on-prem k8s are
legitimate air-gapped uses) — this diff only checks the three excluded cloud
SDKs, matching \`scripts/airgap-dependency-guard.sh\`'s own scope.
EOF
