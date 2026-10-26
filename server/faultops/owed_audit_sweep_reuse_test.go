// owed_audit_sweep_reuse_test.go -- the soundness gate for the world reuse in
// TestOwedAuditOracle_SweepEveryScopedOp (owed_audit_oracle_calibration_test.go).
//
// The sweep runs each op's cases on one reference + faulted world pair reset in place
// (owedSweepReusedDrive). TestWorldReuseSoundness proves that reset sound for the
// FuzzStorageFaultOperations corpus; this file proves it for the sweep's own ops and
// fault grid: the same sweep code (owedCalSweepOp), run once with fresh worlds per
// case and once with the reused pair, must evaluate the same cases and reach the same
// verdict on each. TestOwedAuditOracle_SweepReuseCatchesPlantedStateLeak is the red
// half: a reset that leaks the pending-audit table must make the comparison, and the
// reused sweep itself, fail.
package faultops

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"testing"
)

// owedSweepReuseEquivEnv set to "all" makes the gate cover every scoped op instead of
// owedSweepReuseSampleOps (a manual run: about the sweep's own cost, twice).
const owedSweepReuseEquivEnv = "KEYORIX_OWED_SWEEP_REUSE_EQUIV"

// owedSweepReuseSampleOps is what the gate covers in an ordinary run: the
// calibration's group-member removal, and the SCIM group delete, whose route family a
// reused world once lacked (faultWorldRouterConfig).
var owedSweepReuseSampleOps = []string{owedCalOp, "REST DELETE /scim/v2/Groups/{id}"}

// TestOwedAuditOracle_SweepReuseMatchesFreshWorlds runs the sweep for each covered op
// with fresh worlds and with the reused pair and compares them case by case: the same
// case set; per case the same drive outcome, the same result, the same before/after/
// reference state outside the outcome-log tables, the same outcome-log rows once the
// httptest port is masked, and the same oracle findings.
func TestOwedAuditOracle_SweepReuseMatchesFreshWorlds(t *testing.T) {
	ops := owedSweepReuseSampleOps
	if os.Getenv(owedSweepReuseEquivEnv) == "all" {
		ops = owedAuditScopedOps()
	}
	for _, op := range ops {
		if !owedAuditRuleOp(op) {
			t.Fatalf("gate op %q is not in the rule's scope: the sweep never runs it", op)
		}
	}
	compared := 0
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			fresh, reused := owedSweepBothWays(t, op)
			compared += owedSweepCompare(t, fresh, reused)
		})
	}
	if compared == 0 {
		t.Fatal("no observed case was compared: the gate would pass vacuously")
	}
	t.Logf("reuse gate: %d ops, %d observed cases identical with fresh and reused worlds", len(ops), compared)
}

// owedSweepBothWays runs owedCalSweepOp for op with fresh worlds, then with a reused
// pair, and returns each run's cases by name. Each run is its own subtest, so the
// sweep's own t.Errorf findings fail the gate too.
func owedSweepBothWays(t *testing.T, op string) (fresh, reused map[string]owedSweepCase) {
	t.Helper()
	kinds, nths := owedSweepGrid()
	run := func(name string, drive func(t *testing.T) owedSweepDrive) map[string]owedSweepCase {
		got := map[string]owedSweepCase{}
		t.Run(name, func(t *testing.T) {
			var accepted, same, neverFired, notSuccess int
			var multiOwed []string
			owedCalSweepOp(t, op, kinds, nths, drive(t), func(c owedSweepCase) {
				if _, dup := got[c.name]; dup {
					t.Errorf("case %s evaluated twice", c.name)
				}
				got[c.name] = c
			}, &accepted, &same, &neverFired, &notSuccess, &multiOwed)
		})
		return got
	}
	fresh = run("fresh", func(*testing.T) owedSweepDrive { return owedSweepFreshDrive })
	reused = run("reused", owedSweepReusedDrive)
	return fresh, reused
}

// owedSweepCompare reports every difference between the two runs and returns how
// many observed cases matched.
func owedSweepCompare(t *testing.T, fresh, reused map[string]owedSweepCase) int {
	t.Helper()
	names := slices.Sorted(maps.Keys(fresh))
	if r := slices.Sorted(maps.Keys(reused)); !slices.Equal(names, r) {
		t.Errorf("case sets differ: fresh %v, reused %v", names, r)
		return 0
	}
	matched := 0
	for _, name := range names {
		if diff := owedSweepCaseDiff(fresh[name], reused[name]); diff != "" {
			t.Errorf("%s: reused world differs from fresh worlds: %s", name, diff)
			continue
		}
		if fresh[name].outcome == driveObserved {
			matched++
		}
	}
	return matched
}

// owedSweepPortRE and owedSweepTimeRE mask what two worlds never share, fresh or
// reused: the httptest server's ephemeral port (assertVerdictsMatch's outcome-log
// carve-out has the history) and wall-clock timestamps in response bodies
// (expires_at, created_at; the snapshot already ignores time columns).
var (
	owedSweepPortRE = regexp.MustCompile(`127\.0\.0\.1:\d+`)
	owedSweepTimeRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}(:|%3A)\d{2}(:|%3A)\d{2}(\.\d+)?(Z|[+-]\d{2}(:|%3A)\d{2})?`)
)

func owedSweepMask(s string) string {
	return owedSweepTimeRE.ReplaceAllString(owedSweepPortRE.ReplaceAllString(s, "127.0.0.1:PORT"), "TIME")
}

// owedSweepCaseDiff is "" when a and b are the same verdict, else what differs.
func owedSweepCaseDiff(a, b owedSweepCase) string {
	switch {
	case a.outcome != b.outcome:
		return "drive outcome"
	case a.why != b.why:
		return "why: " + a.why + " / " + b.why
	case a.outcome != driveObserved:
		return ""
	case a.in.result.Success != b.in.result.Success:
		return "result success"
	case owedSweepMask(a.in.result.Detail) != owedSweepMask(b.in.result.Detail):
		return "result detail: " + a.in.result.Detail + " / " + b.in.result.Detail
	}
	snaps := []struct {
		label string
		x, y  dbSnapshot
	}{{"before", a.in.before, b.in.before}, {"after", a.in.after, b.in.after}, {"refAfter", a.in.refAfter, b.in.refAfter}}
	for _, s := range snaps {
		if hashExcluding(s.x, outcomeLogTables...) != hashExcluding(s.y, outcomeLogTables...) {
			return s.label + " state outside the outcome-log tables"
		}
		for _, tbl := range outcomeLogTables {
			if d := owedSweepRowsDiff(s.x.Tables[tbl].Rows, s.y.Tables[tbl].Rows); d != "" {
				return s.label + " " + tbl + " rows: " + d
			}
		}
	}
	if !slices.Equal(owedSweepMasked(a.findings), owedSweepMasked(b.findings)) {
		return "oracle findings"
	}
	return ""
}

// owedSweepRowsDiff is "" when the masked rows are equal, else the first difference.
func owedSweepRowsDiff(x, y []string) string {
	mx, my := owedSweepMasked(x), owedSweepMasked(y)
	if len(mx) != len(my) {
		return fmt.Sprintf("%d rows / %d rows", len(mx), len(my))
	}
	for i := range mx {
		if mx[i] != my[i] {
			return mx[i] + " / " + my[i]
		}
	}
	return ""
}

func owedSweepMasked(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = owedSweepMask(s)
	}
	return out
}

// TestOwedAuditOracle_SweepReuseCatchesPlantedStateLeak is the gate's red proof: with
// resetWorldTables leaking the pending-audit table between cases, the comparison must
// find a difference, and the reused sweep must report a finding of its own (a reuse
// defect must not make the sweep go green on what it is there to catch).
func TestOwedAuditOracle_SweepReuseCatchesPlantedStateLeak(t *testing.T) {
	if os.Getenv("KEYORIX_RUN_REDPROOF_TESTS") == "" {
		t.Skip("manual red-proof, skipped by default: set KEYORIX_RUN_REDPROOF_TESTS=1. It plants a state leak, so " +
			"its nested subtests fail by design; look for \"planted state leak correctly detected\".")
	}
	const leaked = "pending_audit_events"
	probe := buildReusableFaultWorld(t, nil)
	if !probe.db.Migrator().HasTable(leaked) {
		t.Fatalf("plant target table %q does not exist: the plant would be a silent no-op", leaked)
	}
	fresh := map[string]owedSweepCase{}
	reused := map[string]owedSweepCase{}
	t.Run("leaky", func(t *testing.T) {
		leakTableForTest = leaked
		defer func() { leakTableForTest = "" }()
		fresh, reused = owedSweepBothWays(t, owedCalOp)
	})
	mismatches, reusedFindings := 0, 0
	for name, f := range fresh {
		if owedSweepCaseDiff(f, reused[name]) != "" {
			mismatches++
		}
		if len(reused[name].findings) > 0 {
			reusedFindings++
		}
	}
	if mismatches == 0 || reusedFindings == 0 {
		t.Fatalf("planted pending-audit leak: %d of %d cases differ from fresh worlds, %d reused cases have findings; "+
			"both must be non-zero or the gate (or the sweep) does not see a reuse defect", mismatches, len(fresh), reusedFindings)
	}
	t.Logf("planted state leak correctly detected: %d of %d cases differ, %d reused cases reported findings",
		mismatches, len(fresh), reusedFindings)
}
