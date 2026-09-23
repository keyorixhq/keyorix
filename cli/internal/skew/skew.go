// Package skew implements the CLI side of ADR-108 Decision 3's tiered version-skew rule
// (docs/cli-split-inventory.md §5). The server exposes exactly two fields on the
// unauthenticated GET /api/v1/version: api_version (an integer epoch, bumped only on a
// breaking REST change) and minimum_cli_version (a semver floor, empty when unset). This
// package turns those two fields, plus the CLI's own compiled identity, into one of three
// outcomes: refuse, warn-but-proceed, or fully compatible.
//
// The two fields serve two independent purposes, checked in this order:
//
//  1. minimum_cli_version is a hard POLICY floor an operator sets explicitly (e.g. to force
//     an upgrade after a CLI-side security fix). Below it, or on a different major line
//     entirely, refuse outright -- this check wins regardless of the epoch check below.
//  2. api_version is a soft EPOCH-drift signal. A CLI whose compiled TargetAPIVersion lags
//     the server's (the server moved to a newer, additive epoch) is usually still fine --
//     warn "upgrade available" rather than block. A CLI whose TargetAPIVersion is AHEAD of
//     the server's may call a route the server genuinely lacks; this package can only warn
//     in general here, the per-request 404 remapper (internal/apiclient) gives the precise
//     "server too old for this command" error when a specific gap is actually hit.
package skew

import "fmt"

// Result is the outcome of comparing this CLI's identity against a server's advertised
// version-skew fields.
type Result struct {
	// Refuse is true when the CLI must not proceed at all.
	Refuse bool
	// Reason explains why, set only when Refuse is true.
	Reason string
	// Warning is a non-fatal advisory to print before proceeding, set only when Refuse is
	// false and a soft skew was detected.
	Warning string
}

// Check classifies version skew between this CLI build and a server's advertised
// api_version / minimum_cli_version. cliVersion is the CLI's own compiled release semver
// (cliversion.Version); cliTargetAPI is the API epoch this CLI build was written against
// (cliversion.TargetAPIVersion). serverMinCLI may be empty (no floor configured).
func Check(cliVersion string, cliTargetAPI int, serverAPI int, serverMinCLI string) Result {
	if serverMinCLI != "" {
		cliV, err1 := parseSemver(cliVersion)
		minV, err2 := parseSemver(serverMinCLI)
		if err1 == nil && err2 == nil {
			if cliV.major != minV.major {
				return Result{
					Refuse: true,
					Reason: fmt.Sprintf("this CLI (%s) is on a different major version line than the server requires (minimum %s) -- install a CLI on the %d.x line", cliVersion, serverMinCLI, minV.major),
				}
			}
			if cliV.less(minV) {
				return Result{
					Refuse: true,
					Reason: fmt.Sprintf("this CLI (%s) is older than the server's required minimum (%s) -- upgrade the CLI to continue", cliVersion, serverMinCLI),
				}
			}
		}
		// A CLI/server build tagged "dev" (or any other non-semver string) can't be
		// compared numerically -- fall through to the epoch check rather than refusing
		// on a parse error alone; a dev build failing open here is deliberate (it can
		// never be what a real operator's minimum_cli_version enforcement is protecting
		// against), not an oversight.
	}

	switch {
	case serverAPI == cliTargetAPI:
		return Result{}
	case serverAPI > cliTargetAPI:
		return Result{
			Warning: fmt.Sprintf("this CLI targets API version %d, but the server is on %d -- an upgrade is available", cliTargetAPI, serverAPI),
		}
	default: // serverAPI < cliTargetAPI: this CLI is newer than the server's epoch.
		return Result{
			Warning: fmt.Sprintf("server API version %d is older than this CLI expects (%d) -- some commands may report \"server too old for this command\"", serverAPI, cliTargetAPI),
		}
	}
}

type semver struct {
	major, minor, patch int
}

func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// parseSemver accepts "MAJOR.MINOR.PATCH", an optional leading "v", and ignores any
// "-prerelease"/"+build" suffix. It intentionally does not implement full semver precedence
// (pre-release ordering) -- this package only needs major/minor/patch comparison.
func parseSemver(s string) (semver, error) {
	s = trimPrefix(s, "v")
	s = cutSuffix(cutSuffix(s, "-"), "+")

	var v semver
	n, err := fmt.Sscanf(s, "%d.%d.%d", &v.major, &v.minor, &v.patch)
	if err != nil || n != 3 {
		return semver{}, fmt.Errorf("not a MAJOR.MINOR.PATCH version: %q", s)
	}
	return v, nil
}

func trimPrefix(s, prefix string) string {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// cutSuffix returns s truncated at the first occurrence of sep, or s unchanged if sep does
// not occur.
func cutSuffix(s, sep string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			return s[:i]
		}
	}
	return s
}
