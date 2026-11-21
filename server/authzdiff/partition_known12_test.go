package authzdiff

import "testing"

// TestKnown12AbsorbsOnlyBadRequest pins the REST status known-12 absorbs on
// the three V5EXT5 MFA ops: the business-rule 400 ("MFA is not enabled" / "no
// pending MFA enrolment") is waived, a 500 on the same shape is a server fault
// and stays "unexplained", so a strict sweep fails on it.
func TestKnown12AbsorbsOnlyBadRequest(t *testing.T) {
	gap := []string{"mapping-gap:rest"}
	for _, op := range []string{"mfa.activate", "mfa.disable", "mfa.recovery-codes.regenerate"} {
		for _, c := range []struct {
			detail, want string
		}{
			{"Bad Request", "known-12"},
			{"Internal Server Error", "unexplained"},
		} {
			r := caseResult{
				caseKey: caseKey{Op: op, Principal: pkViewer, Target: "self"}, Model: Denied, Classes: gap,
				Legs: map[layer]*legOutcome{layerCore: legOut(Other, "untyped-error"), layerREST: legOut(Other, c.detail), layerGRPC: {NA: "no gRPC method"}},
			}
			if got := explain(&r); got != c.want {
				t.Errorf("%s, REST %s: explain = %q, want %q", op, c.detail, got, c.want)
			}
		}
	}
}
