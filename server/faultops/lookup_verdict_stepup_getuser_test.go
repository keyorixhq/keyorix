// lookup_verdict_stepup_getuser_test.go — AUTH-ENDPOINT-OUTAGE-1 item 3 (#3873).
//
// POST /api/v1/auth/mfa/stepup reads the caller's own account before any code is
// evaluated. A fault there answered 401 ("user not found") and stood as two #3873
// oracle (h) tolerance rows. It now answers 503; this drives both kinds through the
// real harness and the whole oracle, with no tolerance, so the rows cannot come back
// silently.
package faultops

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestLookupVerdict_StepUpGetUserFaultIs503(t *testing.T) {
	const op = "REST POST /api/v1/auth/mfa/stepup"
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
		t.Run(kind.String(), func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, op, "GetUser", 1, kind)
			if outcome != driveObserved {
				t.Fatalf("could not be driven (%s: %s)", outcome, reason)
			}
			if !strings.HasPrefix(in.result.Detail, "HTTP 503") {
				t.Fatalf("a GetUser fault before any code was evaluated must answer 503, got %q", in.result.Detail)
			}
			if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) > 0 {
				t.Fatalf("the oracle reports: %v", f)
			}
		})
	}
}
