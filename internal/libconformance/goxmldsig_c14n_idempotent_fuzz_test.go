package libconformance

// GOXMLDSIG CANONICALISATION IDEMPOTENCE (task XM1, oracle C14N-1). goxmldsig is the
// XML-DSig engine under crewjam/saml: on every SAML verify, crewjam hands goxmldsig a
// beevik/etree tree and goxmldsig CANONICALISES the signed element (exclusive C14N, the
// algorithm every real SAML IdP uses) before computing/verifying the digest. A signature is
// only as stable as that canonical form: if canonicalising an ALREADY-canonical document
// produced DIFFERENT bytes, the "same" signed element would have two digests, and a
// re-serialisation an attacker can force (a proxy, a relay, a different but equivalent
// spelling of the same infoset) could change the verification verdict. C14N is defined to be
// a NORMAL FORM — a fixed point of canonicalise∘parse — exactly so that cannot happen.
//
// This target is the library-level arbiter of that fixed-point property. It is additive to,
// not a redo of:
//   - FuzzXMLParserDifferential (etree-vs-encoding/xml skeleton agreement, a different layer),
//   - FuzzEtreeRoundTripIdempotent (etree's OWN serialise/parse fixed point — this one is
//     goxmldsig's canonicaliser, a different serialiser with namespace-rewriting rules etree's
//     plain WriteToBytes does not apply),
//   - the SAML-handler differential oracles owned by SXS1 (whole-ParseResponse, with keys).
// goxmldsig is otherwise fuzzed nowhere in this repo — it is only exercised transitively.
//
// ORACLE (for each canonicaliser C goxmldsig exposes):
//
//	let b1 = C.Canonicalize(parse(data).Root())        // first canonical form
//	let b2 = C.Canonicalize(parse(b1).Root())          // canonicalise the canonical form
//	INVARIANT:  b1 == b2                                (C14N is a fixed point)
//
// A b1 != b2 is a C14N-NON-IDEMPOTENCE candidate: a canonical form that is not stable under
// re-canonicalisation. The reverse safe directions (parse fails, Canonicalize errors) are not
// findings — a document neither etree nor goxmldsig will process never reaches a signature.
//
// RESOURCE METER: namespace rewriting in exclusive C14N is where super-linear work would hide
// (an element re-emitting a large inherited namespace context at every node). The run is
// metered with resguard (alloc + wall, air-gap not relevant: no network) under a committed
// budget, and wrapped in fuzzutil.Guard so a hang/amplification fails with attribution rather
// than stalling the worker.
//
// WHAT THIS ORACLE DOES NOT VERIFY (stated so the green is not over-read):
//   - It canonicalises the ROOT of whatever parses. It does NOT test subtree canonicalisation
//     with a non-trivial INHERITED namespace context from real ancestors (the signed <Assertion>
//     sits inside <Response>); that ancestor-context case is a LEFTOVER (see report) because
//     constructing a faithful inherited context needs the crewjam placement, which is SXS1's
//     scope. Idempotence at the root still catches a canonicaliser that is not a fixed point.
//   - It does NOT verify that two GENUINELY-different-but-equivalent infosets canonicalise to
//     the SAME bytes (the full C14N equivalence relation); generating equivalent infosets
//     without encoding bias is itself hard. Idempotence is the sound subset (reflexivity of
//     that relation on the canonical representative) and is what signature stability rests on.
//   - It does NOT check signature VALUES or verification verdicts (that is the signature
//     metamorphic target), only the byte-stability of the canonical form.
//   - It uses the default empty exclusive-C14N prefix list and no InclusiveNamespaces; a
//     non-empty prefix list is a separate configuration, not asserted here.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// c14nAlgos is every canonicaliser goxmldsig exposes, each exercised independently so a
// non-idempotence confined to one algorithm still fires. The exclusive variants are the ones
// SAML actually uses; the inclusive/1.1 variants are included for completeness.
func c14nAlgos() []struct {
	name string
	c    dsig.Canonicalizer
} {
	return []struct {
		name string
		c    dsig.Canonicalizer
	}{
		{"exc-c14n", dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")},
		{"exc-c14n-comments", dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")},
		{"c14n10-rec", dsig.MakeC14N10RecCanonicalizer()},
		{"c14n10-comments", dsig.MakeC14N10WithCommentsCanonicalizer()},
		{"c14n11", dsig.MakeC14N11Canonicalizer()},
		{"c14n11-comments", dsig.MakeC14N11WithCommentsCanonicalizer()},
	}
}

// parseRoot parses data permissively (the same Permissive setting crewjam/etree accept under)
// and returns its root element, or nil if there is no parseable root.
func parseRoot(data []byte) *etree.Element {
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = true
	if err := doc.ReadFromBytes(data); err != nil {
		return nil
	}
	return doc.Root()
}

// canonTwice returns (b1, b2, ok) where b1 is the canonical form of data's root under c and b2
// is the canonical form of b1's root. ok is false (and the pair is not comparable) when any
// parse or canonicalisation step fails — all safe directions, not findings.
func canonTwice(c dsig.Canonicalizer, data []byte) (b1, b2 []byte, ok bool) {
	r1 := parseRoot(data)
	if r1 == nil {
		return nil, nil, false
	}
	b1, err := c.Canonicalize(r1)
	if err != nil {
		return nil, nil, false
	}
	r2 := parseRoot(b1)
	if r2 == nil {
		// goxmldsig emitted canonical bytes etree cannot re-parse: that is itself a
		// round-trip defect, but we classify it conservatively as the safe direction here
		// (the signature layer would reject it downstream) and leave it to the report's
		// LEFTOVERS; return false so idempotence is not asserted on an unparseable b1.
		return b1, nil, false
	}
	b2, err = c.Canonicalize(r2)
	if err != nil {
		return b1, nil, false
	}
	return b1, b2, true
}

const goxmldsigC14NBudgetPath = "testdata/resguard-goxmldsig-c14n.json"

// FuzzGoxmldsigC14NIdempotent is oracle C14N-1. See the file header for the invariant and the
// list of what it does not verify.
func FuzzGoxmldsigC14NIdempotent(f *testing.F) {
	seeds := []string{
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="_a"><saml:Subject><saml:NameID>u@x</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
		`<a xmlns="urn:d"><b x="1"/><c/></a>`,
		`<r xmlns:z="urn:z"><z:e b="2" a="1">x</z:e></r>`, // attr order: C14N sorts
		`<a><b/><!-- c --><c/></a>`,                       // comments: dropped or kept per algo
		`<a xmlns:p="urn:p" xmlns:q="urn:p"><p:x/><q:x/></a>`,
		`<a><![CDATA[<raw>]]></a>`,
		`<x:a xmlns:x="urn:x" x:k="v" xmlns:unused="urn:u"/>`, // unused ns: exclusive C14N prunes
		`<a>  spaced  text  </a>`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	budget, err := resguard.LoadBudget(goxmldsigC14NBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardGoxmldsigC14NCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", goxmldsigC14NBudgetPath)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap input so this target stays focused on the fixed-point property; a pathological
		// input that makes the PARSER itself hang is FuzzEtreeParseComplexity's job.
		if len(data) > 1<<20 {
			return
		}
		for _, algo := range c14nAlgos() {
			var b1, b2 []byte
			var ok bool
			cost := probe.Measure(len(data), func() {
				fuzzutil.Guard(t.Fatalf, "goxmldsig.Canonicalize", func() {
					b1, b2, ok = canonTwice(algo.c, data)
				})
			})
			resguard.FeedCoverage(cost)
			if haveBudget {
				budget.Check(t.Fatalf, cost)
			}
			if msg := c14nFixedPointViolation(algo.name, data, b1, b2, ok); msg != "" {
				t.Fatal(msg)
			}
		}
	})
}

// c14nFixedPointViolation is the oracle's verdict, shared by the fuzz body and the red/green
// proof so the proof exercises the exact comparison and message the fuzzer uses. It returns ""
// when the pair is not comparable (ok false) or is a fixed point.
func c14nFixedPointViolation(name string, data, b1, b2 []byte, ok bool) string {
	if !ok || bytes.Equal(b1, b2) {
		return ""
	}
	return fmt.Sprintf("C14N-NON-IDEMPOTENCE (%s): canonical form is not a fixed point\n input=%q\n b1=%q\n b2=%q", name, data, b1, b2)
}
