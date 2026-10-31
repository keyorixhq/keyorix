package faultops

// lookup_verdict_status_oracle_proof_test.go — the strength proof of oracle (h)
// (lookup_verdict_status_oracle_test.go), kept in its own file so
// ~/.claude/scripts/redproof.sh can run it against the commit BEFORE #3326's fix
// (628e61a91^) with only the two oracle files copied in, and with no edit to
// production code:
//
//	redproof.sh 628e61a91^ ./server/faultops 'TestLookupVerdictOracle_' \
//	  server/faultops/lookup_verdict_status_oracle_test.go \
//	  server/faultops/lookup_verdict_status_oracle_proof_test.go
//
// It only calls helpers that exist at that commit (driveFaultCase).

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// credentialLookupDriven are real (op, method, nth) cases that reach a credential
// lookup on the authenticated request path. A fault there is an outage, not a
// verdict on the credential: before #3326 it answered 401 (and was negative-
// cached), since then 503. Each must fire, or the proof is vacuous.
var credentialLookupDriven = []struct {
	op, method string
	nth        int
}{
	{"REST POST /api/v1/secrets/", "GetSession", 1},
	{"REST POST /api/v1/secrets/", "GetSession", 2},
	{"REST POST /api/v1/secrets/", "GetUser", 1},
}

// TestLookupVerdictOracle_CredentialLookupFaultIsNotAVerdict drives each case
// through the real harness and requires oracle (h) to find no violation: the
// credential read failed, so the refused request must not carry a 401/403.
func TestLookupVerdictOracle_CredentialLookupFaultIsNotAVerdict(t *testing.T) {
	for _, tc := range credentialLookupDriven {
		t.Run(tc.op+"/"+tc.method, func(t *testing.T) {
			in, outcome, why := driveFaultCase(t, tc.op, tc.method, tc.nth, faultstorage.KindError)
			if outcome != driveObserved {
				t.Fatalf("the fault did not reach the oracle (%s): the proof would be vacuous", why)
			}
			if in.result.Success {
				t.Fatalf("a failed %s must refuse the request, got success: %s", tc.method, in.result.Detail)
			}
			if msg := lookupVerdictViolation(in); msg != "" {
				t.Fatalf("%s", msg)
			}
		})
	}
}
