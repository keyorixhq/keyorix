// besteffort_guard_test.go — internal/core's run of the best-effort-after-commit
// structural guard (GUARD-1; v2 per #2561's coordinator review).
//
// The scanner, its documented blind spots, and its own planted-positive
// calibration all live in internal/besteffortguard. This file is just the
// per-package invocation: scan ".", classify against docs/besteffort-exempt.tsv,
// and assert four things rather than one.
//
// Why four. v1 asserted only "no unclassified hits" and was green in all three
// packages, which established nothing about whether it could ever be red:
// delete the matcher and it stays green forever ("a guard nobody has watched
// fail is not a guard"). Measured afterwards, v1 found 5 hits in this package,
// all of one single callee, behind 12 exemption rows — 7 of which pardoned
// nothing at all.
package core

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/besteffortguard"
)

const (
	// besteffortExemptKey disambiguates this package's rows in the shared TSV.
	besteffortExemptKey  = "internal/core"
	besteffortExemptPath = "../../docs/besteffort-exempt.tsv"

	// besteffortMinPairs / besteffortMinFuncsWithWrite are the floors below
	// which a green result means the SCANNER broke, not that the package got
	// cleaner. Set well under the current numbers (47 pairs, 351
	// write-containing functions) so ordinary refactoring doesn't trip them,
	// but far enough above zero that a matcher silently matching nothing — the
	// exact way a guard rots into a no-op — fails loudly.
	//
	// A floor is a blunt instrument and deliberately so: it cannot tell you
	// WHICH matcher broke, only that the scan's output collapsed. The planted
	// fixture in internal/besteffortguard is what pins the individual shapes.
	besteffortMinPairs          = 35
	besteffortMinFuncsWithWrite = 250
	besteffortMinDiscardSites   = 100
)

func besteffortScan(t *testing.T) *besteffortguard.Result {
	t.Helper()
	res, err := besteffortguard.Scan(".", besteffortguard.Options{})
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	return res
}

func besteffortExemptions(t *testing.T) map[besteffortguard.Key]besteffortguard.Exemption {
	t.Helper()
	exempt, err := besteffortguard.LoadExemptions(besteffortExemptPath, besteffortExemptKey)
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	return exempt
}

// TestBestEffortGuard_UnprotectedPostWriteDiscard is the guard proper: every
// function in this package that drops a call's result after a committed storage
// write must either route it through besteffort.Run, or carry a reviewed
// exemption saying why the callee already recovers internally.
func TestBestEffortGuard_UnprotectedPostWriteDiscard(t *testing.T) {
	unclassified := besteffortguard.Unclassified(besteffortScan(t).Hits, besteffortExemptions(t))
	if len(unclassified) > 0 {
		t.Fatalf("besteffort guard: %d (function, callee) pair(s) drop a call's result after a storage write with no "+
			"reviewed %q entry in %s. Either route the discarded call through besteffort.Run (see internal/besteffort), "+
			"or add a reviewed exemption whose guard column shows why the callee already recovers. Unclassified:\n  %s",
			len(unclassified), besteffortExemptKey+":<function>#<callee>", besteffortExemptPath, strings.Join(unclassified, "\n  "))
	}
}

// TestBestEffortGuard_NoStaleExemptions: every exemption must still pardon a
// real hit. A row matching nothing is the failure mode the coordinator caught
// on evictUserSessionCache, and it is not cosmetic — it inflates the file's
// apparent coverage, and a row left behind after its hit was FIXED silently
// pre-approves the shape coming back.
func TestBestEffortGuard_NoStaleExemptions(t *testing.T) {
	stale := besteffortguard.StaleExemptions(besteffortScan(t).Hits, besteffortExemptions(t))
	if len(stale) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s match no current hit. Delete them: a pardon for nothing "+
			"reads exactly like a load-bearing one, and if its hit was fixed, the fix is now un-guarded.\n  %s",
			len(stale), besteffortExemptPath, strings.Join(stale, "\n  "))
	}
}

// TestBestEffortGuard_ExemptionGuardsHoldInSource re-derives each exemption's
// OWN claim from the source on every run: a callee-recovers row's callee must
// really defer a recover(), and a callee-recovers-via row's named choke point
// must really recover AND really be reachable from the callee. Without this the
// guard column would be the same unverified prose as v1's reason string.
func TestBestEffortGuard_ExemptionGuardsHoldInSource(t *testing.T) {
	problems, err := besteffortguard.VerifyExemptionGuards(".", besteffortExemptions(t))
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s assert panic-safety the source does not show:\n  %s",
			len(problems), besteffortExemptPath, strings.Join(problems, "\n  "))
	}
}

// TestBestEffortGuard_ScanStillFindsSomething guards the CONDITION the three
// tests above depend on. Each of them passes trivially when the scan returns
// nothing, so a matcher that quietly stops matching turns all three green at
// once — indistinguishable from a clean package, and worse, because it looks
// like evidence.
func TestBestEffortGuard_ScanStillFindsSomething(t *testing.T) {
	res := besteffortScan(t)
	pairs := besteffortguard.DistinctPairs(res.Hits)
	if pairs < besteffortMinPairs {
		t.Errorf("besteffort guard: scan found %d distinct (function, callee) pairs, floor is %d. If this package genuinely "+
			"got cleaner, lower the floor IN THE SAME COMMIT as the fixes and say which ones; if not, a matcher in "+
			"internal/besteffortguard has stopped matching.", pairs, besteffortMinPairs)
	}
	if res.Stats.FuncsWithWrite < besteffortMinFuncsWithWrite {
		t.Errorf("besteffort guard: scan detected writes in only %d function(s) of %d, floor is %d -- the write-verb "+
			"matcher has stopped recognising storage writes, so every \"post-write\" verdict above is vacuous",
			res.Stats.FuncsWithWrite, res.Stats.Funcs, besteffortMinFuncsWithWrite)
	}
	if res.Stats.DiscardSites < besteffortMinDiscardSites {
		t.Errorf("besteffort guard: scan found only %d discard site(s) anywhere in the package, floor is %d -- the "+
			"discard matcher has stopped matching", res.Stats.DiscardSites, besteffortMinDiscardSites)
	}
}
