// besteffort_guard_test.go — server/http/handlers' run of the
// best-effort-after-commit structural guard (GUARD-1; v2 per #2561's
// coordinator review). The scanner and its calibration live in
// internal/besteffortguard.
//
// The scan covers this directory and every handlerFamilySubdirs subpackage
// (httpx, reports), each as its own root (see besteffortFamilyDir).
//
// The family currently has ZERO hits, and that is a real result rather than a
// dead check: the scan detects writes in 128 of its 642 functions and finds 30
// discard sites, but every one of those discards textually PRECEDES its
// function's last write, so none can misreport an already-committed operation.
//
// Which is exactly why "no unclassified hits" cannot be the only assertion
// here. On an empty hit set it passes no matter what the scanner does — the
// population is empty, so the verdict is vacuous. The floor below guards the
// precondition instead (CLAUDE.md: "when a verdict depends on a condition,
// guard the condition, not the conclusion"): if the write matcher ever stops
// recognising this package's writes, THAT fails, instead of the guard going
// quietly green forever.
package handlers

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/besteffortguard"
)

const (
	besteffortExemptKey  = "server/http/handlers"
	besteffortExemptPath = "../../../docs/besteffort-exempt.tsv"

	// besteffortWriteReceiverField restricts write-verb matching to calls
	// through this package's established "<handler>.coreService.<Method>(...)"
	// accessor. Without it, Header().Set(...), csv.Writer.Write(...) and
	// json.Encoder.Encode(...) — which these handlers call constantly, and none
	// of which is a storage commit — would all read as writes.
	besteffortWriteReceiverField = "coreService"

	// Floors: see the package comment. Current values, summed over the family, are
	// 128 functions with a detected write and 30 discard sites; these sit well below that so routine
	// handler churn doesn't trip them, and far enough above zero that a broken
	// matcher does.
	besteffortMinFuncsWithWrite = 90
	besteffortMinDiscardSites   = 20
)

// besteffortFamilyDir is one root the guard scans: this directory or one of
// its handlerFamilySubdirs subpackages. besteffortguard.Scan reads only *.go
// files DIRECTLY under a root, so each subpackage is scanned as a root of its
// own; scanning "." alone silently skipped reports/ (RecordHygieneSnapshot
// writes through coreService). Each root is a separate Go package, which is
// what the scanner's package-local return-arity and panic-safety lookups
// assume, and its exemptions are keyed by its own path.
type besteffortFamilyDir struct {
	dir string // relative to this directory
	key string // the <package> column of docs/besteffort-exempt.tsv
}

func besteffortFamilyDirs() []besteffortFamilyDir {
	dirs := []besteffortFamilyDir{{dir: ".", key: besteffortExemptKey}}
	for _, sub := range handlerFamilySubdirs {
		dirs = append(dirs, besteffortFamilyDir{dir: sub, key: besteffortExemptKey + "/" + sub})
	}
	return dirs
}

func besteffortScan(t *testing.T, d besteffortFamilyDir) *besteffortguard.Result {
	t.Helper()
	res, err := besteffortguard.Scan(d.dir, besteffortguard.Options{WriteReceiverField: besteffortWriteReceiverField})
	if err != nil {
		t.Fatalf("besteffort guard: %s: %v", d.key, err)
	}
	return res
}

func besteffortExemptions(t *testing.T, d besteffortFamilyDir) map[besteffortguard.Key]besteffortguard.Exemption {
	t.Helper()
	exempt, err := besteffortguard.LoadExemptions(besteffortExemptPath, d.key)
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	return exempt
}

// besteffortPrefixed qualifies each message with its root's exemption key, so a
// hit in a subpackage names the row that would answer for it.
func besteffortPrefixed(d besteffortFamilyDir, msgs []string) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, d.key+":"+m)
	}
	return out
}

func TestBestEffortGuard_UnprotectedPostWriteDiscard(t *testing.T) {
	var unclassified []string
	for _, d := range besteffortFamilyDirs() {
		unclassified = append(unclassified, besteffortPrefixed(d,
			besteffortguard.Unclassified(besteffortScan(t, d).Hits, besteffortExemptions(t, d)))...)
	}
	if len(unclassified) > 0 {
		t.Fatalf("besteffort guard: %d (function, callee) pair(s) drop a call's result after a storage write with no "+
			"reviewed %q entry in %s. Either route the discarded call through besteffort.Run (see internal/besteffort), "+
			"or add a reviewed exemption whose guard column shows why the callee already recovers. Unclassified:\n  %s",
			len(unclassified), "<package>:<function>#<callee>", besteffortExemptPath, strings.Join(unclassified, "\n  "))
	}
}

// TestBestEffortGuard_NoStaleExemptions: this package has no exemptions today,
// and this is what keeps it that way — adding a row for a hit that doesn't
// exist fails here rather than sitting in the file looking like coverage.
func TestBestEffortGuard_NoStaleExemptions(t *testing.T) {
	var stale []string
	for _, d := range besteffortFamilyDirs() {
		stale = append(stale, besteffortPrefixed(d,
			besteffortguard.StaleExemptions(besteffortScan(t, d).Hits, besteffortExemptions(t, d)))...)
	}
	if len(stale) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s match no current hit. Delete them: a pardon for nothing "+
			"reads exactly like a load-bearing one, and if its hit was fixed, the fix is now un-guarded.\n  %s",
			len(stale), besteffortExemptPath, strings.Join(stale, "\n  "))
	}
}

func TestBestEffortGuard_ExemptionGuardsHoldInSource(t *testing.T) {
	var problems []string
	for _, d := range besteffortFamilyDirs() {
		p, err := besteffortguard.VerifyExemptionGuards(d.dir, besteffortExemptions(t, d))
		if err != nil {
			t.Fatalf("besteffort guard: %s: %v", d.key, err)
		}
		problems = append(problems, besteffortPrefixed(d, p)...)
	}
	if len(problems) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s assert panic-safety the source does not show:\n  %s",
			len(problems), besteffortExemptPath, strings.Join(problems, "\n  "))
	}
}

// TestBestEffortGuard_ScanPreconditionHolds is the load-bearing assertion in
// THIS package, since the hit set is legitimately empty. It fails if the
// scanner stops seeing this package's writes or its discards at all — the only
// way to tell "every discard here precedes its write" apart from "the scanner
// found nothing to look at".
func TestBestEffortGuard_ScanPreconditionHolds(t *testing.T) {
	var funcs, funcsWithWrite, discards int
	for _, d := range besteffortFamilyDirs() {
		res := besteffortScan(t, d)
		if res.Stats.Files == 0 {
			t.Errorf("besteffort guard: %s: the scan read no Go files in %s, so nothing there is checked", d.key, d.dir)
		}
		t.Logf("%s: %d files, %d funcs, %d with a write, %d discard sites",
			d.key, res.Stats.Files, res.Stats.Funcs, res.Stats.FuncsWithWrite, res.Stats.DiscardSites)
		funcs += res.Stats.Funcs
		funcsWithWrite += res.Stats.FuncsWithWrite
		discards += res.Stats.DiscardSites
	}
	if funcsWithWrite < besteffortMinFuncsWithWrite {
		t.Errorf("besteffort guard: scan detected writes in only %d function(s) of %d, floor is %d -- with the "+
			"%q receiver restriction, the write-verb matcher has stopped recognising this package's storage writes, "+
			"so \"0 unclassified hits\" above means nothing",
			funcsWithWrite, funcs, besteffortMinFuncsWithWrite, besteffortWriteReceiverField)
	}
	if discards < besteffortMinDiscardSites {
		t.Errorf("besteffort guard: scan found only %d discard site(s) anywhere in the package, floor is %d -- the "+
			"discard matcher has stopped matching", discards, besteffortMinDiscardSites)
	}
}
