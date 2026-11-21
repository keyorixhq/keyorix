package saml

// Deterministic companions to FuzzSAMLFullIdentity (task SXS1): they pin the oracle and the
// attribute-targeted mutators so the fuzzer cannot go green by being vacuous.

import (
	"bytes"
	"errors"
	"testing"
)

func pristineIdentity() *AssertionInfo {
	return &AssertionInfo{
		Subject: fidSubject, Email: fidEmail, Name: fidName,
		Groups: []string{fidGroup2, fidGroup1}, // order must not matter
	}
}

// The oracle must stay silent on the signed identity and on a rejection, and fire on a
// forged result in EACH field (including the groups-escalation shapes).
func TestFullIdentity_OracleRejectsForgedResults(t *testing.T) {
	if msg := checkFullIdentity(pristineIdentity(), nil, 0, 0); msg != "" {
		t.Fatalf("oracle fired on the pristine signed identity: %s", msg)
	}
	if msg := checkFullIdentity(nil, errors.New("rejected"), 0, 0); msg != "" {
		t.Fatalf("oracle fired on a rejection: %s", msg)
	}

	forge := map[string]func(*AssertionInfo){
		"subject":       func(i *AssertionInfo) { i.Subject = "attacker@corp.example" },
		"email":         func(i *AssertionInfo) { i.Email = "attacker@corp.example" },
		"name":          func(i *AssertionInfo) { i.Name = "Attacker" },
		"group-added":   func(i *AssertionInfo) { i.Groups = append(i.Groups, fidEvilGroup) },
		"group-swap":    func(i *AssertionInfo) { i.Groups = []string{fidEvilGroup, fidGroup2} },
		"group-dropped": func(i *AssertionInfo) { i.Groups = []string{fidGroup1} },
		"group-trunc":   func(i *AssertionInfo) { i.Groups = []string{fidGroup1[:len(fidGroup1)/2], fidGroup2} },
		"groups-empty":  func(i *AssertionInfo) { i.Groups = nil },
	}
	for name, mutate := range forge {
		info := pristineIdentity()
		mutate(info)
		if checkFullIdentity(info, nil, 1, 2) == "" {
			t.Errorf("oracle accepted a forged %s", name)
		}
	}
	if checkFullIdentity(nil, nil, 0, 0) == "" {
		t.Error("oracle accepted nil error with nil AssertionInfo")
	}
}

// The real fixture must verify AND yield exactly the signed identity: if it stopped
// verifying, the fuzzer would reject every op and stay green.
func TestFullIdentity_PristineFixtureAccepted(t *testing.T) {
	fx := newFIDFixture(t)
	info, op, off, perr := mustParse(fx)
	if perr != nil {
		t.Fatalf("pristine signed fixture rejected: %v", perr)
	}
	if msg := checkFullIdentity(info, perr, op, off); msg != "" {
		t.Fatal(msg)
	}
}

// Mutators 15..20 return their input unchanged on a miss; each must actually change the
// signed document, otherwise the op silently degenerates into the pristine accept path.
func TestFullIdentity_AttributeMutatorsAreNotNoOps(t *testing.T) {
	fx := newFIDFixture(t)
	for op := uint8(diffNumOps); op < fidNumOps; op++ {
		out := fidMutate(fx.signedXML, op, 0, []byte("Z"))
		if bytes.Equal(out, fx.signedXML) {
			t.Errorf("op %d left the signed response unchanged (mutator missed its target)", op)
		}
	}
	// The injected group must really be present for the injection ops.
	for _, op := range []uint8{18, 19, 20} {
		if !bytes.Contains(fidMutate(fx.signedXML, op, 0, nil), []byte(fidEvilGroup)) {
			t.Errorf("op %d did not inject %q", op, fidEvilGroup)
		}
	}
}

// Every attribute-targeted op, run through the real provider, must be rejected or yield
// exactly the signed identity (never a changed groups/email/name).
func TestFullIdentity_AttributeOpsNeverChangeIdentity(t *testing.T) {
	fx := newFIDFixture(t)
	for op := uint8(diffNumOps); op < fidNumOps; op++ {
		mutated := fidMutate(fx.signedXML, op, 0, []byte("Z"))
		info, perr := fx.p.ParseResponse(postedReq(fx.acsURL, mutated), nil)
		if msg := checkFullIdentity(info, perr, op, 0); msg != "" {
			t.Errorf("op %d: %s", op, msg)
		}
	}
}
