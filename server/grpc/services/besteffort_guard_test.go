// besteffort_guard_test.go — server/grpc/services' run of the
// best-effort-after-commit structural guard (GUARD-1; v2 per #2561's
// coordinator review). The scanner and its calibration live in
// internal/besteffortguard.
//
// Like server/http/handlers, this package has ZERO hits, and for the same
// reason: the scan detects writes in 36 of its 185 functions, but the single
// discard site in the whole package precedes its write. So the hit-set
// assertion below is vacuous on its own and the precondition floor is what
// actually holds anything (CLAUDE.md: "when a verdict depends on a condition,
// guard the condition, not the conclusion").
//
// Worth stating plainly, since a thin gRPC layer is exactly where one would
// expect this guard to be weakest: these services delegate to internal/core
// rather than performing post-commit best-effort work themselves, which is why
// there is almost nothing here for the guard to find. The guard's real
// population is internal/core.
package services

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/besteffortguard"
)

const (
	besteffortExemptKey  = "server/grpc/services"
	besteffortExemptPath = "../../../docs/besteffort-exempt.tsv"

	// besteffortWriteReceiverField restricts write-verb matching to calls
	// through this package's "<server>.core.<Method>(...)" accessor, for the
	// same reason the HTTP handlers restrict to "coreService": without it,
	// unrelated Set/Add/Close calls on gRPC and stdlib types read as writes.
	besteffortWriteReceiverField = "core"

	// Floors: current values are 36 functions with a detected write and 1
	// discard site. The discard floor is therefore 1 — low, but the point is
	// that it is not zero: if the discard matcher breaks, this fails.
	besteffortMinFuncsWithWrite = 25
	besteffortMinDiscardSites   = 1
)

func besteffortScan(t *testing.T) *besteffortguard.Result {
	t.Helper()
	res, err := besteffortguard.Scan(".", besteffortguard.Options{WriteReceiverField: besteffortWriteReceiverField})
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

func TestBestEffortGuard_UnprotectedPostWriteDiscard(t *testing.T) {
	unclassified := besteffortguard.Unclassified(besteffortScan(t).Hits, besteffortExemptions(t))
	if len(unclassified) > 0 {
		t.Fatalf("besteffort guard: %d (function, callee) pair(s) drop a call's result after a storage write with no "+
			"reviewed %q entry in %s. Either route the discarded call through besteffort.Run (see internal/besteffort), "+
			"or add a reviewed exemption whose guard column shows why the callee already recovers. Unclassified:\n  %s",
			len(unclassified), besteffortExemptKey+":<function>#<callee>", besteffortExemptPath, strings.Join(unclassified, "\n  "))
	}
}

func TestBestEffortGuard_NoStaleExemptions(t *testing.T) {
	stale := besteffortguard.StaleExemptions(besteffortScan(t).Hits, besteffortExemptions(t))
	if len(stale) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s match no current hit. Delete them: a pardon for nothing "+
			"reads exactly like a load-bearing one, and if its hit was fixed, the fix is now un-guarded.\n  %s",
			len(stale), besteffortExemptPath, strings.Join(stale, "\n  "))
	}
}

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

// TestBestEffortGuard_ScanPreconditionHolds is the load-bearing assertion here,
// since the hit set is legitimately empty — see the package comment.
func TestBestEffortGuard_ScanPreconditionHolds(t *testing.T) {
	res := besteffortScan(t)
	if res.Stats.FuncsWithWrite < besteffortMinFuncsWithWrite {
		t.Errorf("besteffort guard: scan detected writes in only %d function(s) of %d, floor is %d -- with the "+
			"%q receiver restriction, the write-verb matcher has stopped recognising this package's storage writes, "+
			"so \"0 unclassified hits\" above means nothing",
			res.Stats.FuncsWithWrite, res.Stats.Funcs, besteffortMinFuncsWithWrite, besteffortWriteReceiverField)
	}
	if res.Stats.DiscardSites < besteffortMinDiscardSites {
		t.Errorf("besteffort guard: scan found only %d discard site(s) anywhere in the package, floor is %d -- the "+
			"discard matcher has stopped matching", res.Stats.DiscardSites, besteffortMinDiscardSites)
	}
}
