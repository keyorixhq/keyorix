// lookup_verdict_pure_read_twin_test.go — AUTH-ENDPOINT-OUTAGE-1 item 3 (#3873).
//
// Oracle (h) excuses a verdict-shaped answer to a lookup fault only through a
// reviewed oracleAByDesignErrors row for the exact (op, method, kind, nth). The
// post-verdict refresh owner read and the WebAuthn finish identity read have such
// rows for KindError (#2880, FIX-3065: answered like a dead credential, the slot
// kept), but by-design rows may not name KindEffectThenError, so their pure-read
// twins stood as #3873 tolerance rows. A KindError row now opts in for oracle (h)
// with lookupVerdictEffectThenError (the reason); lookupVerdictPureReadTwin honours
// it for the effect-then-error run of the same tuple.
//
// What it checks, per opted-in row (TestLookupVerdictPureReadTwin_RowsAreLoadBearing)
//   - the row's tuple driven with both kinds answers byte-identically: the
//     pure-read premise, observed for this tuple, not assumed;
//   - the effect-then-error run passes oracle (h) with the opt-in and is reported
//     by it without (load-bearing);
//   - the same run relabelled to another op or nth is not excused (scoped).
//
// What it does not do: it does not decide the answer is right. That is the KindError
// row's own review; this only stops oracle (h) re-reporting the decided case under
// the other kind label. It never applies to panic.
package faultops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// TestLookupVerdictPureReadTwin_RowsAreScoped: an opted-in row is a pinned KindError
// row on a reviewed pure read with a cited proving test.
func TestLookupVerdictPureReadTwin_RowsAreScoped(t *testing.T) {
	t.Parallel()
	n := 0
	for _, e := range oracleAByDesignErrors {
		if e.lookupVerdictEffectThenError == "" {
			continue
		}
		n++
		label := fmt.Sprintf("%s/%s/%s#%d", e.op, e.method, e.kind, e.nth)
		if e.kind != faultstorage.KindError {
			t.Errorf("%s: lookupVerdictEffectThenError is only meaningful on a KindError row", label)
		}
		if !pureReadMethods[e.method] {
			t.Errorf("%s: %s is not in pureReadMethods", label, e.method)
		}
		if !isLookupFaultMethod(e.method) {
			t.Errorf("%s: %s is not a lookup oracle (h) judges; the opt-in would be dead", label, e.method)
		}
		if e.nth <= 0 {
			t.Errorf("%s: nth must be pinned", label)
		}
		if err := provingTestExists(e.provingTest); err != nil {
			t.Errorf("%s: %v", label, err)
		}
	}
	if n == 0 {
		t.Fatal("no row opts in to lookupVerdictEffectThenError: lookupVerdictPureReadTwin is dead, remove it")
	}
}

// withoutLookupVerdictTwin clears e's oracle (h) opt-in and returns the restore.
func withoutLookupVerdictTwin(e oracleAByDesignError) func() {
	saved := oracleAByDesignErrors
	cp := append([]oracleAByDesignError(nil), saved...)
	for i := range cp {
		if cp[i].op == e.op && cp[i].method == e.method && cp[i].kind == e.kind && cp[i].nth == e.nth {
			cp[i].lookupVerdictEffectThenError = ""
		}
	}
	oracleAByDesignErrors = cp
	return func() { oracleAByDesignErrors = saved }
}

func TestLookupVerdictPureReadTwin_RowsAreLoadBearing(t *testing.T) {
	n := 0
	for _, e := range oracleAByDesignErrors {
		if e.lookupVerdictEffectThenError == "" {
			continue
		}
		n++
		label := fmt.Sprintf("%s/%s#%d", e.op, e.method, e.nth)
		t.Run(strings.ReplaceAll(label, "/", "_"), func(t *testing.T) {
			asErr, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, faultstorage.KindError)
			if outcome != driveObserved {
				t.Fatalf("error kind could not be driven (%s: %s)", outcome, reason)
			}
			ete, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, faultstorage.KindEffectThenError)
			if outcome != driveObserved {
				t.Fatalf("effect-then-error could not be driven (%s: %s)", outcome, reason)
			}
			if asErr.result != ete.result {
				t.Fatalf("premise: effect-then-error answered %+v, the error kind %+v -- not a pure read here", ete.result, asErr.result)
			}
			if !isVerdictShapedAnswer(ete.result) {
				t.Fatalf("the twin answered %q, not a verdict: the opt-in is dead, delete it", ete.result.Detail)
			}
			if msg := lookupVerdictViolation(ete); msg != "" {
				t.Fatalf("with the opt-in oracle (h) still reports: %s", msg)
			}
			if f := oracleFindingsWithout(t, ete, func() func() { return func() {} }); len(f) > 0 {
				t.Fatalf("with the opt-in the oracle still reports: %v", f)
			}
			func() {
				defer withoutLookupVerdictTwin(e)()
				if lookupVerdictViolation(ete) == "" {
					t.Fatal("without the opt-in oracle (h) must report this case")
				}
			}()
			for _, relabel := range []func(*oracleInput){
				func(in *oracleInput) { in.op = "REST POST /api/v1/secrets/" },
				func(in *oracleInput) { in.nth = e.nth + 1 },
			} {
				in := ete
				relabel(&in)
				if lookupVerdictPureReadTwin(in) != nil {
					t.Errorf("accepted the case relabelled as (%s, nth %d)", in.op, in.nth)
				}
			}
			t.Logf("load-bearing: %s effect-then-error == error (%s)", label, strings.TrimSpace(ete.result.Detail))
		})
	}
	if n == 0 {
		t.Fatal("no row opts in to lookupVerdictEffectThenError")
	}
}
