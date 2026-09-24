package skew

import (
	"testing"
)

// FuzzSkewCheck fuzzes Check against arbitrary CLI/server version identity
// tuples. Check's own doc comment (skew.go) documents the exact contract this
// oracle re-derives independently rather than re-asserting Check's own
// internals against themselves:
//
//  1. minimum_cli_version is a hard policy floor, checked FIRST: it refuses
//     the CLI (Result.Refuse) if and only if BOTH cliVersion and
//     serverMinCLI parse as MAJOR.MINOR.PATCH semver AND either the major
//     line differs or cliVersion is below the floor. An unparseable side
//     (e.g. a "dev" build, or garbage server-supplied text) deliberately
//     fails OPEN to the epoch check below rather than refusing on a parse
//     error alone -- skew.go's own comment calls this out by name ("a dev
//     build failing open here is deliberate"), so this is the package's
//     documented fallback for an unparseable/old-style version string, not
//     an oversight this oracle should paper over.
//  2. The epoch check (api_version vs. the CLI's compiled target) can only
//     ever produce "compatible" (empty Result) or "warn" (Result.Warning
//     set) -- it can never refuse.
//  3. Result's own fields are mutually exclusive per its doc comment:
//     Reason is set if and only if Refuse is true; Warning is only ever set
//     when Refuse is false.
//  4. Check never panics on any input, including non-semver, empty, or
//     adversarial strings on either side. (No hang-guard wrapper here,
//     unlike this repo's root-module fuzz targets: internal/fuzzutil lives
//     in the main module, and this cli module deliberately carries zero
//     dependency on it -- ADR-108 Decision A, enforced by
//     cli/internal/depguard. Check is a small, loop-bounded pure function
//     with no I/O, so a hang is not a realistic failure mode here.)
func FuzzSkewCheck(f *testing.F) {
	seeds := []struct {
		cliVersion   string
		cliTargetAPI int
		serverAPI    int
		serverMinCLI string
	}{
		{"1.4.2", 1, 1, "1.0.0"},         // matching versions, fully compatible
		{"1.4.2", 1, 2, "1.0.0"},         // minor skew: server epoch ahead -> warn
		{"1.4.2", 2, 1, "1.0.0"},         // minor skew: CLI epoch ahead -> warn
		{"1.9.9", 1, 1, "2.0.0"},         // major skew vs. minimum -> refuse
		{"1.2.0", 1, 1, "1.5.0"},         // CLI too old vs. minimum -> refuse
		{"1.4.2", 1, 1, "not-a-version"}, // garbage minimum_cli_version -> fails open to epoch check
		{"not-a-version", 1, 1, "1.0.0"}, // garbage/unparseable cliVersion -> fails open to epoch check
		{"", 0, 0, ""},                   // all empty
		{"dev", 1, 1, "1.5.0"},           // dev build fails open (skew.go's own documented case)
	}
	for _, s := range seeds {
		f.Add(s.cliVersion, s.cliTargetAPI, s.serverAPI, s.serverMinCLI)
	}

	f.Fuzz(func(t *testing.T, cliVersion string, cliTargetAPI int, serverAPI int, serverMinCLI string) {
		result := Check(cliVersion, cliTargetAPI, serverAPI, serverMinCLI)

		if result.Refuse {
			if result.Reason == "" {
				t.Fatalf("Refuse=true but Reason is empty (cliVersion=%q cliTargetAPI=%d serverAPI=%d serverMinCLI=%q)", cliVersion, cliTargetAPI, serverAPI, serverMinCLI)
			}
			if result.Warning != "" {
				t.Fatalf("Refuse=true but Warning is also set: %q (cliVersion=%q cliTargetAPI=%d serverAPI=%d serverMinCLI=%q)", result.Warning, cliVersion, cliTargetAPI, serverAPI, serverMinCLI)
			}
		} else if result.Reason != "" {
			t.Fatalf("Refuse=false but Reason is set: %q (cliVersion=%q cliTargetAPI=%d serverAPI=%d serverMinCLI=%q)", result.Reason, cliVersion, cliTargetAPI, serverAPI, serverMinCLI)
		}

		// Independently derive the expected refuse decision from the documented
		// contract above, using the package's own parseSemver (this file is an
		// internal test, package skew) rather than re-deriving semver parsing by
		// hand.
		wantRefuse := false
		if serverMinCLI != "" {
			cliV, err1 := parseSemver(cliVersion)
			minV, err2 := parseSemver(serverMinCLI)
			if err1 == nil && err2 == nil {
				if cliV.major != minV.major || cliV.less(minV) {
					wantRefuse = true
				}
			}
		}
		if result.Refuse != wantRefuse {
			t.Fatalf("Refuse = %v, want %v (cliVersion=%q cliTargetAPI=%d serverAPI=%d serverMinCLI=%q result=%+v)", result.Refuse, wantRefuse, cliVersion, cliTargetAPI, serverAPI, serverMinCLI, result)
		}

		if !result.Refuse {
			wantWarning := serverAPI != cliTargetAPI
			gotWarning := result.Warning != ""
			if gotWarning != wantWarning {
				t.Fatalf("warning present = %v, want %v (cliVersion=%q cliTargetAPI=%d serverAPI=%d serverMinCLI=%q result=%+v)", gotWarning, wantWarning, cliVersion, cliTargetAPI, serverAPI, serverMinCLI, result)
			}
		}
	})
}
