package libconformance

// Baseline (green) and RED-PROOF for oracle X1 (FuzzXMLParserDifferential). Together they
// prove the oracle is not vacuous: the comparator fires on a genuine etree-vs-encoding/xml
// skeleton divergence, the N1/N2/N3 catalogue suppresses only the specific benign classes it
// names (so a NEW class still fires), and the xrv antecedent genuinely filters a dangerous
// namespace-collision class out of the accepted set.

import (
	"bytes"
	"testing"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// TestXMLParserDifferential_Baseline is the green baseline: a genuine SAML-shaped Response is
// accepted by xrv, and etree and encoding/xml build the identical normalized skeleton. If
// this fails, the harness wiring (not a real finding) is wrong — fix the fixture, never the
// assertion.
func TestXMLParserDifferential_Baseline(t *testing.T) {
	doc := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0">` +
		`<saml:Issuer>https://idp.example/entity</saml:Issuer>` +
		`<saml:Assertion ID="_a" Version="2.0"><saml:Issuer>https://idp.example/entity</saml:Issuer>` +
		`<saml:Subject><saml:NameID>user@corp.example</saml:NameID></saml:Subject>` +
		`<saml:Conditions><saml:AudienceRestriction><saml:Audience>sp</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion></samlp:Response>`)

	if err := xrv.Validate(bytes.NewReader(doc)); err != nil {
		t.Fatalf("baseline: xrv rejected a genuine SAML response: %v", err)
	}
	et, ok1 := etreeSkeleton(doc)
	xm, ok2 := xmlSkeleton(doc)
	if !ok1 || !ok2 {
		t.Fatalf("baseline: a parser failed on a genuine response: etree-ok=%v xml-ok=%v", ok1, ok2)
	}
	if !skeletonsEqual(normalizeSkeleton(et), normalizeSkeleton(xm)) {
		t.Fatalf("baseline: etree and encoding/xml disagree on a GENUINE response skeleton\n etree=%v\n xml  =%v", et, xm)
	}
	accepted, finding := checkParserDifferential(doc)
	if !accepted || finding != "" {
		t.Fatalf("baseline: oracle reported on a genuine response: accepted=%v finding=%q", accepted, finding)
	}
}

// TestXMLParserDifferential_RedProof_DetectorAndCatalogue uses the undeclared-prefix vector
// <a:x/>, a REAL input where etree (drops the undeclared prefix to no-namespace) and
// encoding/xml (keeps the prefix as a pseudo-namespace) genuinely disagree. It proves:
//
//   RED  — the raw comparator SEES the divergence (skeletons differ). So the oracle is not
//          blind: a genuine etree-vs-encoding/xml disagreement does reach the comparison.
//   GREEN— the shipped oracle normalizes it away via the catalogued N1 rule (and only N1),
//          so the live fuzz path is green on this known-benign class.
//
// The catalogue is therefore load-bearing: were a NEW, uncatalogued divergence to appear,
// normalizeSkeleton would not remove it and the oracle WOULD fire.
func TestXMLParserDifferential_RedProof_DetectorAndCatalogue(t *testing.T) {
	vec := []byte(`<a:x/>`) // undeclared prefix: well-formed tokens, not namespace-well-formed
	if err := xrv.Validate(bytes.NewReader(vec)); err != nil {
		t.Fatalf("red-proof premise: xrv should ACCEPT the undeclared-prefix vector, got %v", err)
	}
	et, ok1 := etreeSkeleton(vec)
	xm, ok2 := xmlSkeleton(vec)
	if !ok1 || !ok2 {
		t.Fatalf("red-proof premise: both parsers should parse the vector: etree-ok=%v xml-ok=%v", ok1, ok2)
	}
	// RED: raw skeletons differ — the detector fires on a real divergence.
	if skeletonsEqual(et, xm) {
		t.Fatalf("red-proof broken: raw skeletons should DIFFER on <a:x/> (etree=%v xml=%v); the detector cannot be shown to fire", et, xm)
	}
	// GREEN: the shipped, normalized oracle recognises N1 and is quiet.
	if !skeletonsEqual(normalizeSkeleton(et), normalizeSkeleton(xm)) {
		t.Fatalf("catalogue incomplete: N1 should normalize <a:x/> to agreement, got etree=%v xml=%v",
			normalizeSkeleton(et), normalizeSkeleton(xm))
	}
	if _, finding := checkParserDifferential(vec); finding != "" {
		t.Fatalf("shipped oracle should be GREEN on the catalogued N1 vector, got finding=%q", finding)
	}
}

// TestXMLParserDifferential_RedProof_GenuineDivergenceFires plants a genuine, uncatalogued
// structural divergence and confirms the comparator + finding path fire on it. The vector
// <a><b/></a><c/> has two top-level roots; a FULL token walk (allRoots=true, the "planted
// defect" — a model that over-reads past the first root) sees a <c/> element etree's
// single-root view does not. The shipped single-root model normalizes this away (trailing
// content is out of scope), so this is red only against the defect, green on the shipped
// model — exactly the structural difference the fuzz assertion must fire on if a real one is
// ever found.
func TestXMLParserDifferential_RedProof_GenuineDivergenceFires(t *testing.T) {
	vec := []byte(`<a><b/></a><c/>`)
	et, _ := etreeSkeleton(vec)
	full, _ := xmlSkeletonTokens(vec, true) // planted defect: over-reads past the first root
	// RED: against the defective full-walk model, the normalized skeletons differ, so the
	// comparator reports a divergence (the assertion the fuzz body makes WOULD fire).
	if skeletonsEqual(normalizeSkeleton(et), normalizeSkeleton(full)) {
		t.Fatalf("red-proof broken: full-walk model should diverge from etree on a multi-root doc (etree=%v full=%v)", et, full)
	}
	// GREEN: the shipped single-root model agrees, so the live oracle does not false-positive
	// on trailing content (that class is covered at the SAML layer).
	single, _ := xmlSkeleton(vec)
	if !skeletonsEqual(normalizeSkeleton(et), normalizeSkeleton(single)) {
		t.Fatalf("shipped model should agree with etree on the first root (etree=%v single=%v)", et, single)
	}
}

// TestXMLParserDifferential_RedProof_XRVGuardFiltersCollision shows the xrv antecedent is
// genuinely load-bearing: a namespace-collision vector (two distinct prefixes bound to the
// SAME URI, each carrying an attribute of the same local name — the classic XSW attribute
// forge) resolves, in BOTH parsers, to two attributes with the identical qualified name. xrv
// REJECTS it, so checkParserDifferential short-circuits to the safe direction (accepted=false,
// no finding). This is the class the guard exists to remove from the accepted set.
func TestXMLParserDifferential_RedProof_XRVGuardFiltersCollision(t *testing.T) {
	vec := []byte(`<a xmlns:n="urn:x" n:k="1" xmlns:m="urn:x" m:k="2"/>`)
	if err := xrv.Validate(bytes.NewReader(vec)); err == nil {
		t.Fatalf("red-proof premise: xrv should REJECT the namespace-collision vector, but accepted it")
	}
	accepted, finding := checkParserDifferential(vec)
	if accepted {
		t.Fatalf("checkParserDifferential: xrv rejected, so accepted must be false, got true")
	}
	if finding != "" {
		t.Fatalf("checkParserDifferential: a rejected input must yield no finding, got %q", finding)
	}
}
