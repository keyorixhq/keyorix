package libconformance

// Baseline (green) and RED-PROOF for oracle RT1 (FuzzXMLRoundtripContract). Together they
// prove the oracle is not vacuous: the element-skeleton and unmarshal comparators fire on a
// genuine structural round-trip mutation (an injected duplicate element — the XSW primitive),
// the namespace/CDATA normalisation suppresses only the representational classes it names (so
// a NEW structural class still fires), and the xrv verdict is the load-bearing antecedent.
//
// Why the red proof uses an INJECTING re-serialiser rather than a natural vector: empirically
// (see the probe retained in the report), encoding/xml's own RawToken->Encoder->RawToken round
// trip never changes the element skeleton or the unmarshal view on any input xrv accepts — the
// validator catches exactly the structural-mutation class before it can reach the comparator.
// That is the property under test, so to show the comparator WOULD fire if such a mutation
// ever slipped past xrv, the proof substitutes a re-serialiser that performs the mutation (an
// overflow that duplicates the first child element) and confirms the oracle body reports it.

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// acceptAllValidator is the stub that lets every input past the xrv gate, so the red proof can
// drive the round-trip comparators directly.
func acceptAllValidator([]byte) error { return nil }

// injectingReserialise DUPLICATES the first depth-1 child element in the token stream, then
// re-serialises — a faithful token-level model of an encoding/xml overflow that forges a
// second <Assertion> (the classic SAML signature-wrapping primitive xrv exists to block). It
// operates on tokens (not the mangled byte output), so it is independent of how the encoder
// re-spells namespace prefixes. It is test-only.
func injectingReserialise(raw []xml.Token) ([]byte, bool) {
	// Locate the first child element: the StartElement that opens at depth 1 and its matching
	// EndElement that closes back to depth 1.
	depth := 0
	start, end := -1, -1
	for i, t := range raw {
		switch t.(type) {
		case xml.StartElement:
			if depth == 1 && start < 0 {
				start = i
			}
			depth++
		case xml.EndElement:
			depth--
			if depth == 1 && start >= 0 && end < 0 {
				end = i
			}
		}
	}
	if start < 0 || end < 0 || end < start {
		return reserialise(raw) // nothing to duplicate; behave like the shipped path
	}
	injected := make([]xml.Token, 0, len(raw)+(end-start+1))
	injected = append(injected, raw[:end+1]...)      // up to and including the first child's end
	injected = append(injected, raw[start:end+1]...) // the forged duplicate
	injected = append(injected, raw[end+1:]...)       // the rest
	return reserialise(injected)
}

// TestXMLRoundtripContract_Baseline is the green baseline: a genuine SAML-shaped Response is
// accepted by xrv, its element skeleton and unmarshal view are stable across the real
// encoding/xml round trip, and the oracle reports nothing. If this fails, the harness wiring
// (not a real finding) is wrong — fix the fixture, never the assertion.
func TestXMLRoundtripContract_Baseline(t *testing.T) {
	doc := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0">` +
		`<saml:Issuer>https://idp.example/entity</saml:Issuer>` +
		`<saml:Assertion ID="_a" Version="2.0"><saml:Subject><saml:NameID>user@corp.example</saml:NameID></saml:Subject></saml:Assertion>` +
		`</samlp:Response>`)

	if err := xrv.Validate(bytes.NewReader(doc)); err != nil {
		t.Fatalf("baseline: xrv rejected a genuine SAML response: %v", err)
	}
	accepted, finding := checkRoundtripContract(doc)
	if !accepted {
		t.Fatalf("baseline: xrv accepted, so accepted must be true")
	}
	if finding != "" {
		t.Fatalf("baseline: oracle reported on a genuine round-trip-stable response: %q", finding)
	}
	// The real round trip is genuinely stable: assert the comparators directly.
	_, raw1, ok := decodeRaw(doc)
	if !ok {
		t.Fatalf("baseline: genuine response did not tokenise")
	}
	b2, ok := reserialise(raw1)
	if !ok {
		t.Fatalf("baseline: encoder refused a genuine response")
	}
	_, raw2, ok := decodeRaw(b2)
	if !ok {
		t.Fatalf("baseline: re-serialised genuine response did not parse")
	}
	if !rtStreamsEqual(elementSeq(raw1), elementSeq(raw2)) {
		t.Fatalf("baseline: element skeleton changed across a genuine round trip\n before=%v\n after =%v", elementSeq(raw1), elementSeq(raw2))
	}
	u1, _ := unmarshalSkeleton(doc)
	u2, _ := unmarshalSkeleton(b2)
	if u1 != u2 {
		t.Fatalf("baseline: unmarshal view changed across a genuine round trip\n before=%q\n after =%q", u1, u2)
	}
}

// TestXMLRoundtripContract_RedProof_ComparatorFiresOnInjection proves the oracle is not blind:
// with the xrv gate stubbed open AND a re-serialiser that forges a duplicate <saml:Assertion>,
// the oracle FIRES (reports an ELEMENT-SKELETON or UNMARSHAL mutation). The SHIPPED path
// (real reserialise) is quiet on the same input, so the fire is attributable to the planted
// overflow, not to the harness.
func TestXMLRoundtripContract_RedProof_ComparatorFiresOnInjection(t *testing.T) {
	doc := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Assertion ID="_a"><saml:Subject><saml:NameID>u@x</saml:NameID></saml:Subject></saml:Assertion>` +
		`</samlp:Response>`)

	// RED: accept-all gate + injecting re-serialiser -> the oracle body reaches the comparators
	// and reports the forged duplicate element.
	accepted, finding := checkRoundtripContractFull(acceptAllValidator, injectingReserialise, doc)
	if !accepted {
		t.Fatalf("red-proof: accept-all stub must yield accepted=true")
	}
	if finding == "" {
		t.Fatalf("red-proof BROKEN: the comparator did not fire on a forged duplicate <saml:Assertion> — the oracle would be vacuous")
	}
	if !strings.Contains(finding, "ELEMENT-SKELETON MUTATION") && !strings.Contains(finding, "UNMARSHAL ROUND-TRIP DIVERGENCE") {
		t.Fatalf("red-proof: expected an element-skeleton or unmarshal finding, got %q", finding)
	}

	// GREEN: the SHIPPED re-serialiser (real encoding/xml) is stable on the same input, so the
	// live oracle does not false-positive here. xrv also accepts it, so the full shipped oracle
	// is quiet.
	acceptedS, findingS := checkRoundtripContract(doc)
	if !acceptedS || findingS != "" {
		t.Fatalf("shipped oracle should be GREEN on this genuine response: accepted=%v finding=%q", acceptedS, findingS)
	}
}

// TestXMLRoundtripContract_RedProof_XRVGuardLoadBearing shows the xrv antecedent controls
// whether the round-trip body runs. For an input xrv REJECTS, checkRoundtripContract
// short-circuits to accepted=false with no finding (even though, under an accept-all stub with
// the injecting re-serialiser, the very same bytes drive the comparator to fire). So the xrv
// verdict is the load-bearing gate: it is what keeps the structural-mutation class out of the
// accepted set.
func TestXMLRoundtripContract_RedProof_XRVGuardLoadBearing(t *testing.T) {
	// A namespace-collision document xrv REJECTS (two prefixes bound to the same URI, each
	// carrying an attribute of the same local name — the XSW attribute forge; xrv's job).
	vec := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Assertion xmlns:n="urn:x" n:k="1" xmlns:m="urn:x" m:k="2"/>` +
		`</samlp:Response>`)
	if err := xrv.Validate(bytes.NewReader(vec)); err == nil {
		t.Fatalf("red-proof premise: xrv should REJECT the namespace-collision vector, but accepted it")
	}
	// Shipped oracle: xrv rejected -> short-circuit, no finding.
	accepted, finding := checkRoundtripContract(vec)
	if accepted {
		t.Fatalf("checkRoundtripContract: xrv rejected, so accepted must be false, got true")
	}
	if finding != "" {
		t.Fatalf("checkRoundtripContract: a rejected input must yield no finding, got %q", finding)
	}
	// With the gate stubbed open AND the injecting re-serialiser, the SAME bytes reach and fire
	// the comparator — proving the gate (not an empty comparator) is what kept the shipped path
	// quiet.
	acceptedStub, findingStub := checkRoundtripContractFull(acceptAllValidator, injectingReserialise, vec)
	if !acceptedStub || findingStub == "" {
		t.Fatalf("with accept-all + injection the comparator must fire on the same bytes (accepted=%v finding=%q)", acceptedStub, findingStub)
	}
}
