package healthscan

import (
	"fmt"
	"strconv"
	"strings"
)

// versionPolicy is this build's embedded knowledge of Vault/OpenBao's release and licensing
// history — G2's "no network call to HashiCorp" requirement means this table can never be
// fetched live, so it is necessarily a snapshot that goes stale between releases of
// keyorix-migrate itself. TableAsOf is surfaced in the version check's evidence text precisely
// so a report never implies more freshness than this build actually has.
type versionPolicy struct {
	// TableAsOf is the date this policy was last checked against each vendor's own release
	// notes — not a guarantee about what's shipped since, just an honest freshness marker.
	TableAsOf string

	// VaultLatestKnownMinor / OpenBaoLatestKnownMinor are the latest minor version this build
	// knows about for each product. HashiCorp's own documented CE support policy covers the
	// latest and two prior minors (N-2); OpenBao's own support window isn't something this tool
	// has confident, citable knowledge of, so an OpenBao EOL verdict is deliberately reported at
	// lower confidence (info, not medium/high) — see openBaoEOLSeverity.
	VaultLatestKnownMinor   int
	OpenBaoLatestKnownMinor int

	// VaultBSLMinor is the first Vault minor version licensed under the Business Source License
	// (1.14, 2023-08-10) — HashiCorp Vault before this was MPL 2.0. OpenBao is always MPL-2.0
	// (the entire reason for the fork was staying on the last pre-BSL, MPL-licensed codebase).
	VaultBSLMinor int
}

var currentVersionPolicy = versionPolicy{
	TableAsOf:               "2026-09-01",
	VaultLatestKnownMinor:   17,
	OpenBaoLatestKnownMinor: 2,
	VaultBSLMinor:           14,
}

// detectedVersion is what checkVersion derives from sys/health's version string.
type detectedVersion struct {
	Raw     string
	Product string // "Vault" or "OpenBao"
	License string // "BSL-1.1" or "MPL-2.0"
	Major   int
	Minor   int
	EOL     bool
	// EOLConfidence is "high" for Vault (a documented, citable N-2 policy) and "low" for
	// OpenBao (this build has no citable OpenBao support-window policy — see versionPolicy's
	// doc comment) — carried into the finding's evidence text rather than silently asserting
	// the same confidence for both products.
	EOLConfidence string
}

// parseVaultVersion classifies a sys/health version string against currentVersionPolicy.
// OpenBao is distinguished from Vault by major version: OpenBao's fork started at 2.0.0, and
// Vault's own versioning has never reached 2.x as of this table's TableAsOf — a heuristic, not
// a certainty, and documented as such here rather than asserted silently. If Vault ever ships a
// 2.x release, this heuristic needs revisiting (it would misclassify Vault 2.x as OpenBao).
func parseVaultVersion(raw string) (detectedVersion, error) {
	core, _, _ := strings.Cut(raw, "+") // strip Enterprise/build metadata suffix, e.g. "1.15.6+ent".
	core = strings.TrimPrefix(core, "v")
	parts := strings.SplitN(core, ".", 3)
	if len(parts) < 2 {
		return detectedVersion{}, fmt.Errorf("unrecognized version string %q", raw)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return detectedVersion{}, fmt.Errorf("unrecognized version string %q: %w", raw, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return detectedVersion{}, fmt.Errorf("unrecognized version string %q: %w", raw, err)
	}

	dv := detectedVersion{Raw: raw, Major: major, Minor: minor}
	if major >= 2 {
		dv.Product = "OpenBao"
		dv.License = "MPL-2.0"
		dv.EOL = minor < currentVersionPolicy.OpenBaoLatestKnownMinor-2
		dv.EOLConfidence = "low"
		return dv, nil
	}
	dv.Product = "Vault"
	if minor >= currentVersionPolicy.VaultBSLMinor {
		dv.License = "BSL-1.1"
	} else {
		dv.License = "MPL-2.0"
	}
	dv.EOL = minor < currentVersionPolicy.VaultLatestKnownMinor-2
	dv.EOLConfidence = "high"
	return dv, nil
}
