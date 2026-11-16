package libconformance

import (
	"os"
	"testing"

	"github.com/beevik/etree"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// TestGoxmldsigSignatureMetamorphicRedGreen is the committed red/green proof for oracle SIG-1.
//
// It first establishes the GATE is not vacuous: a benign signed document actually VERIFIES
// (before==true, exercised==true) — otherwise the oracle would pass only because nothing ever
// reaches the tamper step.
//
// GREEN: with the production tamper (add an attribute to the signed root), the tampered document
// does NOT verify (after==false) — so the fuzz body's `before && after` fatal does not fire on
// correct behaviour.
// RED: with a NO-OP tamper (modelling a broken library that fails to detect modification), the
// document still verifies after "tampering" (after==true), so `before && after` is true and the
// oracle WOULD fatal — proving the comparator is load-bearing.
func TestGoxmldsigSignatureMetamorphicRedGreen(t *testing.T) {
	h := getSigHarness()
	if !h.ok {
		t.Skip("could not build goxmldsig signing harness")
	}
	seed := []byte(`<Assertion ID="_a" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Subject><NameID>u@x</NameID></Subject></Assertion>`)

	// GATE + GREEN: real tamper is rejected, and the gate genuinely opened.
	before, after, exercised := signAndMaybeTamper(h, seed)
	if !exercised {
		t.Fatalf("GATE: the benign seed must produce a VERIFYING signature so the oracle is exercised (exercised=false means the test is vacuous)")
	}
	if !before {
		t.Fatalf("GATE: the freshly signed seed must verify before tamper (before=false)")
	}
	if after {
		t.Fatalf("GREEN: adding an attribute to the signed root must break verification, but it still verified")
	}

	// RED: a no-op tamper models a library that fails to detect modification; the oracle's
	// `before && after` condition must then be true.
	noop := func(*etree.Element) {}
	rBefore, rAfter, rExercised := signAndTamperWith(h, seed, noop)
	if !(rExercised && rBefore) {
		t.Fatalf("RED precondition: the signed seed must verify and be exercised")
	}
	if !rAfter {
		t.Fatalf("RED: with a no-op tamper the document must still verify (after=true) so the oracle fires; got after=false")
	}
	if !(rBefore && rAfter) {
		t.Fatalf("RED: the oracle's fatal condition (before && after) must hold under a no-op tamper")
	}
	t.Logf("RED fired as expected: a no-op 'tamper' leaves the document verifying (before=%v after=%v)", rBefore, rAfter)
}

// calibrateGoxmldsigSig derives the resource budget from the benign seed corpus (sign + verify
// + tamper + verify per input), per-byte slope. RSA sign/verify dominates alloc/wall and is
// roughly input-independent, so the floor carries most of the budget — stated in the report.
func calibrateGoxmldsigSig(tb testing.TB) resguard.Budget {
	tb.Helper()
	h := getSigHarness()
	if !h.ok {
		tb.Skip("could not build goxmldsig signing harness")
	}
	seeds := [][]byte{
		[]byte(`<Assertion ID="_a" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Subject><NameID>u@x</NameID></Subject></Assertion>`),
		[]byte(`<a><b x="1">t</b><c/></a>`),
		[]byte(`<r xmlns:z="urn:z"><z:e a="1">x</z:e></r>`),
		[]byte(`<doc><id>42</id><payload>data</payload></doc>`),
	}
	var costs []resguard.Cost
	for range 6 {
		for _, s := range seeds {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, p.Measure(len(s), func() {
				_, _, _ = signAndMaybeTamper(h, s)
			}))
		}
	}
	return resguard.Calibrate("goxmldsig_sig", costs, resguard.DefaultFactor)
}

// TestResguardGoxmldsigSigCalibrate regenerates the committed budget when RESGUARD_CALIBRATE=1.
func TestResguardGoxmldsigSigCalibrate(t *testing.T) {
	b := calibrateGoxmldsigSig(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(goxmldsigSigBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", goxmldsigSigBudgetPath, b.Summary())
	}
}
