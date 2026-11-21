package saml

// Deterministic companions to FuzzSAMLFullIdentity (task SXS1): they pin the oracle and the
// attribute-targeted mutators so the fuzzer cannot go green by being vacuous.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
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

// Every op returns its input unchanged on a miss (missing target, parse failure); each must
// actually change the signed document, otherwise the op silently degenerates into the
// pristine accept path. Covers ops 0..fidNumOps, including op 4's NameID splice.
func TestFullIdentity_AllOpsChangeTheDocument(t *testing.T) {
	fx := newFIDFixture(t)
	for op := range uint8(fidNumOps) {
		out := fidMutate(fx.signedXML, op, 0, []byte("Z"))
		if bytes.Equal(out, fx.signedXML) {
			t.Errorf("op %d left the signed response unchanged (mutator missed its target)", op)
		}
	}
	// The injected group must really be present for the injection ops.
	for op := uint8(18); op <= 23; op++ {
		if !bytes.Contains(fidMutate(fx.signedXML, op, 0, nil), []byte(fidEvilGroup)) {
			t.Errorf("op %d did not inject %q", op, fidEvilGroup)
		}
	}
}

// naiveIdentity is a deliberately broken reader: it takes identity from one unverified
// assertion (the first or last one in document order) the way an SP that regressed into
// reading an unsigned sibling or wrapper would.
func naiveIdentity(t *testing.T, doc []byte, last bool) *AssertionInfo {
	t.Helper()
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		t.Fatalf("mutated response does not parse: %v", err)
	}
	as := d.Root().FindElements(".//Assertion")
	if len(as) == 0 {
		t.Fatal("mutated response has no Assertion")
	}
	a := as[0]
	if last {
		a = as[len(as)-1]
	}
	info := &AssertionInfo{}
	if n := a.FindElement("./Subject/NameID"); n != nil {
		info.Subject = n.Text()
	}
	for _, at := range a.FindElements("./AttributeStatement/Attribute") {
		for _, v := range at.FindElements("./AttributeValue") {
			switch at.SelectAttrValue("FriendlyName", at.SelectAttrValue("Name", "")) {
			case "mail":
				info.Email = v.Text()
			case "cn":
				info.Name = v.Text()
			case "eduPersonAffiliation":
				info.Groups = append(info.Groups, v.Text())
			}
		}
	}
	return info
}

// Red side for ops 21-23: fed through a naive reader, they must reach the oracle's GROUPS
// check (not stop at subject/email/name), which proves the fuzzer can generate the
// "signed NameID, different groups" shape. The real provider rejecting them is asserted by
// TestFullIdentity_AttributeOpsNeverChangeIdentity.
func TestFullIdentity_EvilAssertionOpsReachGroupsCheck(t *testing.T) {
	fx := newFIDFixture(t)
	cases := []struct {
		op   uint8
		last bool // which assertion the naive reader trusts for this placement
	}{
		{21, false}, // evil is the first child
		{22, true},  // evil is appended after the signed one
		{23, false}, // evil is the outer assertion
	}
	for _, c := range cases {
		mutated := fidMutate(fx.signedXML, c.op, 0, nil)
		info := naiveIdentity(t, mutated, c.last)
		msg := checkFullIdentity(info, nil, c.op, 0)
		if !strings.Contains(msg, "(groups)") {
			t.Errorf("op %d: naive reader result did not reach the groups check: %q", c.op, msg)
		}
		// And the naive reader reading the signed assertion instead must stay clean, so the
		// oracle is firing on the injected assertion and not on the fixture.
		if clean := naiveIdentity(t, fx.signedXML, false); checkFullIdentity(clean, nil, c.op, 0) != "" {
			t.Fatalf("naive reader does not reproduce the signed identity on the pristine fixture")
		}
	}
}

// Every op (structural and attribute-targeted), run through the real provider, must be
// rejected or yield exactly the signed identity (never a changed subject/groups/email/name).
func TestFullIdentity_AttributeOpsNeverChangeIdentity(t *testing.T) {
	fx := newFIDFixture(t)
	for op := range uint8(fidNumOps) {
		mutated := fidMutate(fx.signedXML, op, 0, []byte("Z"))
		info, perr := fx.p.ParseResponse(postedReq(fx.acsURL, mutated), nil)
		if msg := checkFullIdentity(info, perr, op, 0); msg != "" {
			t.Errorf("op %d: %s", op, msg)
		}
	}
}
