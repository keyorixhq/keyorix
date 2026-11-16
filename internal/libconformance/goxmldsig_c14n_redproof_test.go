package libconformance

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// nonIdempotentCanon wraps a real canonicaliser and appends a per-call nonce, so the SECOND
// canonicalisation of the same bytes differs from the first. It models exactly the defect the
// idempotence oracle exists to catch (a canonical form that is not a fixed point) without
// touching any production code — goxmldsig.Canonicalizer is an interface, so the oracle runs
// against this stand-in unchanged.
type nonIdempotentCanon struct {
	inner dsig.Canonicalizer
	calls int
}

func (c *nonIdempotentCanon) Canonicalize(el *etree.Element) ([]byte, error) {
	b, err := c.inner.Canonicalize(el)
	if err != nil {
		return nil, err
	}
	c.calls++
	return append(b, []byte(fmt.Sprintf("<!--n%d-->", c.calls))...), nil
}

func (c *nonIdempotentCanon) Algorithm() dsig.AlgorithmID { return c.inner.Algorithm() }

// TestGoxmldsigC14NIdempotenceRedGreen is the committed red/green proof for oracle C14N-1.
//
// GREEN: the REAL exclusive-C14N canonicaliser is a fixed point on a benign, namespace-rich
// document — b1 == b2 — so the oracle does not fire on correct behaviour.
// RED: a deliberately non-idempotent canonicaliser (real output + a per-call nonce) produces
// b1 != b2, and the exact comparator the fuzz body uses (bytes.Equal) fires. This proves the
// oracle detects a canonical form that is not stable under re-canonicalisation.
func TestGoxmldsigC14NIdempotenceRedGreen(t *testing.T) {
	seed := []byte(`<r xmlns:z="urn:z" xmlns:unused="urn:u"><z:e b="2" a="1">x</z:e><z:e a="1" b="2"/></r>`)

	// GREEN: real canonicaliser is idempotent.
	real := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	b1, b2, ok := canonTwice(real, seed)
	if !ok {
		t.Fatalf("GREEN precondition: real canonicalisation of the seed must succeed twice")
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("GREEN: real exclusive-C14N is expected to be idempotent, but b1=%q b2=%q", b1, b2)
	}

	// RED: a non-idempotent canonicaliser must be caught by the same comparator.
	bad := &nonIdempotentCanon{inner: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")}
	rb1, rb2, rok := canonTwice(bad, seed)
	if !rok {
		t.Fatalf("RED precondition: the non-idempotent stub must still canonicalise twice")
	}
	if bytes.Equal(rb1, rb2) {
		t.Fatalf("RED: the non-idempotent canonicaliser was expected to break the fixed point, but b1==b2 (%q)", rb1)
	}
	t.Logf("RED fired as expected: b1=%q b2=%q", rb1, rb2)
}

// calibrateGoxmldsigC14N derives the resource budget from the benign seed corpus (every seed
// canonicalised under every algorithm), with the alloc/wall per-byte slope — the right model
// for a parser/serialiser whose work scales with input, NOT a decompression target.
func calibrateGoxmldsigC14N(tb testing.TB) resguard.Budget {
	tb.Helper()
	seeds := [][]byte{
		[]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="_a"><saml:Subject><saml:NameID>u@x</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`),
		[]byte(`<a xmlns="urn:d"><b x="1"/><c/></a>`),
		[]byte(`<r xmlns:z="urn:z"><z:e b="2" a="1">x</z:e></r>`),
		[]byte(`<a xmlns:p="urn:p" xmlns:q="urn:p"><p:x/><q:x/></a>`),
		[]byte(`<x:a xmlns:x="urn:x" x:k="v" xmlns:unused="urn:u"/>`),
	}
	var costs []resguard.Cost
	for range 4 { // repeat to average GC/alloc noise into the p99
		for _, s := range seeds {
			for _, algo := range c14nAlgos() {
				p := resguard.New(tb, resguard.Options{SampleEvery: 1})
				costs = append(costs, p.Measure(len(s), func() {
					_, _, _ = canonTwice(algo.c, s)
				}))
			}
		}
	}
	return resguard.Calibrate("goxmldsig_c14n", costs, resguard.DefaultFactor)
}

// TestResguardGoxmldsigC14NCalibrate regenerates the committed budget when
// RESGUARD_CALIBRATE=1; otherwise it asserts calibration produces an alloc budget.
func TestResguardGoxmldsigC14NCalibrate(t *testing.T) {
	b := calibrateGoxmldsigC14N(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(goxmldsigC14NBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", goxmldsigC14NBudgetPath, b.Summary())
	}
}

// TestResguardGoxmldsigC14NBudgetRedGreen proves the resguard wiring in the fuzz body is
// load-bearing: the benign corpus passes the committed budget (GREEN), and a synthetic Cost an
// order of magnitude over the alloc ceiling trips Check (RED). The synthetic RED is used
// because a deterministic C14N input that amplifies alloc 10x over a benign document is not
// readily constructible here; the amplification-shape detection itself is proven in
// resguard's own package tests. This test proves the budget is attached and fires.
func TestResguardGoxmldsigC14NBudgetRedGreen(t *testing.T) {
	b, err := resguard.LoadBudget(goxmldsigC14NBudgetPath)
	if err != nil {
		t.Skipf("no committed budget (%v); run calibrate first", err)
	}

	// GREEN: a benign canonicalisation stays under budget.
	seed := []byte(`<r xmlns:z="urn:z"><z:e b="2" a="1">x</z:e></r>`)
	p := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := p.Measure(len(seed), func() {
		_, _, _ = canonTwice(dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), seed)
	})
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign canonicalisation (alloc=%d for %d bytes) must not trip the budget", green.AllocBytes, len(seed))
	}

	// RED: a synthetic Cost 10x over the alloc ceiling must trip Check. The ceiling is the
	// public slope factor·(Floor + PerByte·N), recomputed here from the committed budget's
	// exported fields (not a private helper) so this test exercises the same arithmetic Check
	// applies.
	mb := b.Meters["alloc_bytes"]
	ceiling := b.Factor * (mb.Floor + mb.PerByte*float64(len(seed)))
	over := uint64(ceiling*10) + 1
	red := resguard.Cost{InputLen: len(seed), Sampled: true, AllocBytes: over}
	if !b.Check(func(string, ...any) {}, red) {
		t.Fatalf("RED: a Cost with alloc=%d (10x over budget) must trip Check", over)
	}
}
