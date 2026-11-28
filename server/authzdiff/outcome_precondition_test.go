package authzdiff

import (
	"net/http"
	"slices"
	"testing"
)

// The account-state ops have no load-bearing RBAC gate for the precondition they
// carry; an unmet precondition is a business-rule 400. The original three
// (mfa.activate, mfa.disable, mfa.recovery-codes.regenerate) check the caller's own
// MFA state; Stage 3 (V5EXT8/9) added impersonation.end (the bearer must be an
// impersonation session) and webauthn.deleteCredential (the caller must re-auth with
// a second factor) — both answer a 400 for an unmet caller-state precondition. These
// tests pin the PreconditionFailed vocabulary that replaced waiver known-12 (#4525):
// what maps to it, and that every divergence from it is left "unexplained".

var accountStateOps = []string{
	"mfa.activate", "mfa.disable", "mfa.recovery-codes.regenerate",
	"impersonation.end", "webauthn.deleteCredential", "mfa.enroll",
}

// TestRestOutcomePreconditionFailed: only a 400 carrying a precondition message
// is PreconditionFailed; every other status and every other 400 keeps its old
// mapping, so no other op's outcome moves.
func TestRestOutcomePreconditionFailed(t *testing.T) {
	for _, c := range []struct {
		code int
		body string
		want Outcome
	}{
		{http.StatusBadRequest, `{"message":"MFA is not enabled"}`, PreconditionFailed},
		{http.StatusBadRequest, `{"message":"no pending MFA enrolment; begin enrolment first"}`, PreconditionFailed},
		{http.StatusBadRequest, `{"message":"user not found"}`, PreconditionFailed},
		{http.StatusBadRequest, `{"message":"invalid code or password"}`, PreconditionFailed},
		{http.StatusBadRequest, `{"message":"Invalid request body"}`, Other},
		{http.StatusBadRequest, ``, Other},
		{http.StatusForbidden, `{"message":"MFA is not enabled"}`, Denied},
		{http.StatusUnauthorized, `{"message":"MFA is not enabled"}`, Denied},
		{http.StatusOK, `{"message":"MFA is not enabled"}`, Allowed},
		{http.StatusInternalServerError, `{"message":"MFA is not enabled"}`, Other},
	} {
		if got := restOutcome(c.code, c.body, mfaPreconditionMsgs...).Outcome; got != c.want {
			t.Errorf("restOutcome(%d, %q) = %s, want %s", c.code, c.body, got, c.want)
		}
	}
}

// TestRestOutcomeNoPreconditionWithoutOpMessages: an op that names no
// precondition messages never gets PreconditionFailed, whatever its 400 says.
func TestRestOutcomeNoPreconditionWithoutOpMessages(t *testing.T) {
	for _, body := range []string{`{"message":"MFA is not enabled"}`, `{"message":"user not found"}`, `{"message":"invalid code or password"}`} {
		if got := restOutcome(http.StatusBadRequest, body).Outcome; got != Other {
			t.Errorf("restOutcome(400, %q) without op messages = %s, want %s", body, got, Other)
		}
	}
}

// TestPreconditionDivergencesAreUnexplained: for each account-state op, a REST
// leg that disagrees with a PreconditionFailed model (200, 403, 500) or answers
// PreconditionFailed where the model denies is flagged AND no waiver absorbs it;
// the matching pair is clean. This is what known-12 used to hide.
func TestPreconditionDivergencesAreUnexplained(t *testing.T) {
	_, fx := template(t)
	p := fx.principals[pkViewer]
	for _, op := range accountStateOps {
		spec := specByName(t, op)
		for _, c := range []struct {
			name      string
			model     Outcome
			rest      *legOutcome
			wantClass string // "" = no class (agreement)
		}{
			{"precondition=precondition", PreconditionFailed, legOut(PreconditionFailed, "Bad Request"), ""},
			{"denied=denied", Denied, legOut(Denied, "Forbidden"), ""},
			{"rest 200, model precondition", PreconditionFailed, legOut(Allowed, "OK"), "O2:allowed-but-model-precondition-fails:rest"},
			{"rest 403, model precondition", PreconditionFailed, legOut(Denied, "Forbidden"), "O2:denied-but-model-precondition-fails:rest"},
			{"rest 500, model precondition", PreconditionFailed, legOut(Other, "Internal Server Error"), "mapping-gap:other-where-model-precondition-fails:rest"},
			{"rest precondition, model denies", Denied, legOut(PreconditionFailed, "Bad Request"), "O2:precondition-but-model-denied:rest"},
			{"rest precondition, model allows", Allowed, legOut(PreconditionFailed, "Bad Request"), "O2:precondition-but-model-allowed:rest"},
			{"rest 200, model denies", Denied, legOut(Allowed, "OK"), "O2:allowed-but-model-denies:rest"},
			{"rest 400 other, model denies", Denied, legOut(Other, "Bad Request"), "mapping-gap:other-where-model-denies:rest"},
		} {
			r := &caseResult{
				caseKey: caseKey{Op: op, Principal: pkViewer, Target: "self"}, Model: c.model,
				Legs: map[layer]*legOutcome{layerCore: legOut(Other, "untyped-error"), layerREST: c.rest, layerGRPC: {NA: "no gRPC method"}},
			}
			r.Classes = classify(spec, p, r)
			if c.wantClass == "" {
				if len(r.Classes) != 0 {
					t.Errorf("%s / %s: classes = %v, want none", op, c.name, r.Classes)
				}
				continue
			}
			if !slices.Contains(r.Classes, c.wantClass) {
				t.Errorf("%s / %s: classes = %v, want %s", op, c.name, r.Classes, c.wantClass)
			}
			if got := explain(r); got != "unexplained" {
				t.Errorf("%s / %s: explain = %q, want unexplained (no waiver may absorb it)", op, c.name, got)
			}
		}
	}
}

// TestAccountStateOnlyOnTheMFAOps: requirement.accountState is the only way an
// op's model says PreconditionFailed, and it is set on exactly the ops in
// accountStateOps whose handlers answer a business-rule 400 for an unmet
// caller-state precondition. An op using it that is NOT in that list would move
// its outcomes out of Denied without this list noticing.
func TestAccountStateOnlyOnTheMFAOps(t *testing.T) {
	_, fx := template(t)
	var got []string
	for _, spec := range ops() {
		for _, tg := range spec.targets {
			if spec.req(fx, tg, 0).accountState {
				got = append(got, spec.name)
				break
			}
		}
	}
	slices.Sort(got)
	if want := slices.Sorted(slices.Values(accountStateOps)); !slices.Equal(got, want) {
		t.Errorf("ops with requirement.accountState = %v, want %v", got, want)
	}
}
