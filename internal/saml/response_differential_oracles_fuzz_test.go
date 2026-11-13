package saml

// Shared mutation engine for the SAML response differential (task SD1), plus oracle S1.
// The S2 and S3 oracles live in response_differential_s2_fuzz_test.go and
// response_differential_s3_fuzz_test.go; all three share diffFixture (see
// response_differential_fuzz_test.go) and diffMutate below.
//
// diffMutate starts from ONE genuinely-signed response and applies fuzz-directed
// structural + byte-level mutations covering the task's enumerated classes: signature
// wrapping (sibling / wrapped / duplicated assertion), namespace tricks, duplicate/missing
// Subject & Conditions, comments inside NameID, wrong Audience, expired windows, unsigned
// assertion beside the signed one, and an EncryptedAssertion (xmlenc) wrapper.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// diffNumOps is the number of distinct mutation operations diffMutate knows.
const diffNumOps = 15

// diffEvilAssertion is a well-formed but UNSIGNED assertion asserting diffEvilSubject,
// carrying a matching AudienceRestriction so the XSW attempt is not rejected purely on
// audience. It is the payload a wrapping/injection mutation tries to get the SP to read
// instead of the genuinely-signed assertion.
var diffEvilAssertion = fmt.Sprintf(
	`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_evil" IssueInstant="2024-01-01T00:00:00Z">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject>`+
		`<saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">`+
		`<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>`+
		`<saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z"><saml:AuthnContext>`+
		`<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>`+
		`</saml:AuthnContext></saml:AuthnStatement></saml:Assertion>`,
	diffIDPEntityID, diffEvilSubject, diffSPEntityID)

// diffEvilWithAdvice is the evil assertion with an empty Advice slot, used by the "wrap
// the signed assertion inside an evil assertion's Advice" mutation.
var diffEvilWithAdvice = strings.Replace(diffEvilAssertion,
	`</saml:AuthnStatement></saml:Assertion>`,
	`</saml:AuthnStatement><saml:Advice></saml:Advice></saml:Assertion>`, 1)

func parseFragment(s string) *etree.Element {
	d := etree.NewDocument()
	if err := d.ReadFromString(s); err != nil || d.Root() == nil {
		return etree.NewElement("broken")
	}
	return d.Root().Copy()
}

func sanitizeComment(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "--", ""), ">", "")
}

// commentSpliceSubject inserts an XML comment into the middle of the signed NameID text
// (C14N-without-comments strips it, so the enveloped signature stays valid, but a naive
// reader could split the identifier).
func commentSpliceSubject(signed, blob []byte) []byte {
	idx := bytes.Index(signed, []byte(diffSubject))
	if idx < 0 {
		return signed
	}
	k := len(diffSubject) / 2
	comment := "<!--" + sanitizeComment(string(blob)) + "-->"
	out := make([]byte, 0, len(signed)+len(comment))
	out = append(out, signed[:idx+k]...)
	out = append(out, comment...)
	out = append(out, signed[idx+k:]...)
	return out
}

// diffMutate produces one mutated raw SAML response (bytes, not base64) from the pristine
// signed response, selected by op and parameterised by off/blob. Structural ops use etree;
// a parse failure or a missing target element falls back to returning the input unchanged
// (so the op simply becomes a no-op for that iteration rather than corrupting the corpus).
func diffMutate(signed []byte, op uint8, off uint16, blob []byte) []byte {
	switch op % diffNumOps {
	case 13: // raw blob insertion at an offset
		o := int(off) % (len(signed) + 1)
		out := make([]byte, 0, len(signed)+len(blob))
		out = append(out, signed[:o]...)
		out = append(out, blob...)
		out = append(out, signed[o:]...)
		return out
	case 14: // epilogue: a comment after the root element closes
		return append(append([]byte{}, signed...), []byte("<!--"+sanitizeComment(string(blob))+"-->")...)
	case 4: // comment splice inside the signed NameID text
		return commentSpliceSubject(signed, blob)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil {
		return signed
	}
	root := doc.Root()
	if root == nil {
		return signed
	}
	signedAssertion := root.FindElement(".//Assertion")

	switch op % diffNumOps {
	case 0: // evil (unsigned) assertion as the FIRST child of root — classic sibling XSW
		root.InsertChildAt(0, parseFragment(diffEvilAssertion))
	case 1: // evil assertion appended AFTER the signed one
		root.AddChild(parseFragment(diffEvilAssertion))
	case 2: // duplicate the signed assertion (two identical, same ID)
		if signedAssertion != nil {
			root.AddChild(signedAssertion.Copy())
		}
	case 3: // wrap: evil assertion holds the signed assertion inside its Advice
		if signedAssertion != nil {
			evil := parseFragment(diffEvilWithAdvice)
			if adv := evil.FindElement(".//Advice"); adv != nil {
				adv.AddChild(signedAssertion.Copy())
			}
			root.RemoveChild(signedAssertion)
			root.AddChild(evil)
		}
	case 5: // namespace trick: an Assertion-named element in a DIFFERENT namespace at root
		ev := parseFragment(strings.Replace(diffEvilAssertion,
			"urn:oasis:names:tc:SAML:2.0:assertion", "urn:oasis:names:tc:SAML:2.0:assertion:evil", 1))
		root.AddChild(ev)
	case 6: // remove Subject from the signed assertion (breaks signature)
		if signedAssertion != nil {
			if s := childByTag(signedAssertion, "Subject"); s != nil {
				signedAssertion.RemoveChild(s)
			}
		}
	case 7: // remove Conditions from the signed assertion (breaks signature)
		if signedAssertion != nil {
			if c := childByTag(signedAssertion, "Conditions"); c != nil {
				signedAssertion.RemoveChild(c)
			}
		}
	case 8: // duplicate Subject inside the signed assertion
		if signedAssertion != nil {
			if s := childByTag(signedAssertion, "Subject"); s != nil {
				signedAssertion.AddChild(s.Copy())
			}
		}
	case 9: // duplicate Conditions inside the signed assertion
		if signedAssertion != nil {
			if c := childByTag(signedAssertion, "Conditions"); c != nil {
				signedAssertion.AddChild(c.Copy())
			}
		}
	case 10: // xmlenc variant: wrap the signed assertion in EncryptedAssertion + add evil plaintext
		if signedAssertion != nil {
			enc := parseFragment(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
			enc.AddChild(signedAssertion.Copy())
			root.RemoveChild(signedAssertion)
			root.AddChild(enc)
			root.AddChild(parseFragment(diffEvilAssertion))
		}
	case 11: // wrong Audience inside the signed assertion (breaks signature)
		if signedAssertion != nil {
			if aud := signedAssertion.FindElement(".//Audience"); aud != nil {
				aud.SetText("https://attacker.example/")
			}
		}
	case 12: // expire the signed assertion's window (breaks signature)
		if signedAssertion != nil {
			if c := childByTag(signedAssertion, "Conditions"); c != nil {
				setAttr(c, "NotOnOrAfter", "2000-01-01T00:00:00Z")
			}
		}
	}

	out, err := doc.WriteToBytes()
	if err != nil {
		return signed
	}
	return out
}

// addDiffSeeds bootstraps the corpus with one representative input per mutation op.
func addDiffSeeds(f *testing.F) {
	for op := range diffNumOps {
		f.Add(uint8(op), uint16(0), []byte("x"))
	}
	f.Add(uint8(13), uint16(16), []byte("<saml:NameID>z</saml:NameID>"))
	f.Add(uint8(4), uint16(0), []byte("c"))
}

// refParse runs the crewjam reference SP's ParseResponse, recovering a panic in the
// library into (panicked=true) — a crewjam panic is NOT a Keyorix finding, so the S1
// caller treats it as "reference inconclusive" and skips the crewjam comparison for that
// input rather than reporting a false divergence.
func refParse(sp *csaml.ServiceProvider, raw []byte) (err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked, err = true, fmt.Errorf("crewjam panic: %v", r)
		}
	}()
	_, err = sp.ParseResponse(diffReq(raw), nil)
	return err, panicked
}

// FuzzSAMLResponseAcceptAgreement — ORACLE S1.
//
// Invariant: accept(Keyorix) ⟹ accept(crewjam-reference-same-trust), AND Keyorix never
// accepts a response for which goxmldsig validates no assertion signature. A violation is
// a case where Keyorix's wrapper is LOOSER than the library it wraps or than an
// independent signature check — the only security-relevant direction here. The reverse
// (crewjam accepts, Keyorix rejects) is over-strict/EXPECTED-DIFFERENCE and is not failed.
func FuzzSAMLResponseAcceptAgreement(f *testing.F) {
	fx := newDiffFixture(f)
	signed, err := base64.StdEncoding.DecodeString(fx.signedB64)
	if err != nil {
		f.Fatal(err)
	}
	addDiffSeeds(f)

	f.Fuzz(func(t *testing.T, op uint8, off uint16, blob []byte) {
		mutated := diffMutate(signed, op, off, blob)

		var kInfo *AssertionInfo
		var kErr error
		fuzzutil.Guard(t.Fatalf, "saml.diff.S1.keyorix", func() {
			kInfo, kErr = fx.p.ParseResponse(diffReq(mutated), nil)
		})
		if kErr != nil {
			return // Keyorix rejected — the safe outcome; over-strict vs crewjam is fine.
		}
		if kInfo == nil {
			t.Fatalf("S1: Keyorix returned nil error AND nil identity (op=%d)", op)
		}

		cErr, panicked := refParse(fx.refSP, mutated)
		if !panicked && cErr != nil {
			t.Fatalf("S1 DIVERGENCE: Keyorix ACCEPTED (subject=%q) a response the crewjam reference REJECTED: %v (op=%d off=%d)",
				kInfo.Subject, cErr, op, off)
		}

		if _, n := fx.signedIdentities(mutated); n == 0 {
			t.Fatalf("S1 DIVERGENCE: Keyorix ACCEPTED (subject=%q) a response goxmldsig found NO valid signature in (op=%d off=%d)",
				kInfo.Subject, op, off)
		}
	})
}
