package core

import (
	"bytes"
	"testing"

	"github.com/beevik/etree"
)

// FuzzEtreeRoundTripIdempotent is a metamorphic round-trip fuzzer for beevik/etree — the
// XML library under crewjam/saml, i.e. on keyorix's SAML call path. It asserts two
// properties that must hold for any correct parse/serialise pair and that a XSW-class
// discrepancy violates (a serializer that emits XML it re-reads differently is exactly the
// hole mattermost/xml-roundtrip-validator exists to defend against):
//
//   - RE-PARSEABILITY: whatever etree serialises must be re-parseable by etree. A serializer
//     that produces output it cannot itself read back is a defect.
//   - IDEMPOTENCE: serialisation reaches a fixed point within TWO normalisation rounds —
//     serialise(parse(x)) settles to a byte form that is stable under a further round
//     (f(f(f(x))) == f(f(x))). A serialiser whose output never stops changing means the
//     "same" document has no single byte form, the seam XSW attacks slip through. One extra
//     round is allowed for a few infoset-invariant spellings that settle on round 2 rather
//     than round 1 (e.g. an empty CDATA section `<a><![CDATA[]]></a>`, the only construct
//     that parses to a zero-length CharData node: etree first emits `<a></a>`, then on
//     re-parse `<a/>` — both the identical empty element). See
//     FINDING-etree-empty-cdata-nonidempotent-roundtrip.
//
// Both are sound: they assert equalities that hold for any correct round-trip, so there is no
// false-positive direction. (XXE/entity-expansion is NOT asserted here: Go's encoding/xml,
// which etree builds on, does not resolve external or DTD entities, so that class is closed by
// construction rather than by this harness.)
func FuzzEtreeRoundTripIdempotent(f *testing.F) {
	f.Add([]byte(`<a><b x="1">t</b><c/></a>`))
	f.Add([]byte(`<r xmlns:z="urn:z"><z:e a="1" b="2">x</z:e></r>`))
	f.Add([]byte(`<!-- c --><a>&amp;<![CDATA[<raw>]]></a>`))
	f.Add([]byte(``))
	f.Add([]byte(`<a><![CDATA[]]></a>`))        // empty CDATA: settles on round 2 (regression seed)
	f.Add([]byte(`<a><b><![CDATA[]]></b></a>`)) // nested empty CDATA

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(data); err != nil {
			return // only well-formed inputs exercise the round-trip
		}
		s1, err := doc.WriteToBytes()
		if err != nil {
			return
		}

		// RE-PARSEABILITY (round 1): whatever etree serialises must re-parse.
		doc2 := etree.NewDocument()
		if err := doc2.ReadFromBytes(s1); err != nil {
			t.Fatalf("ROUND-TRIP: etree serialised output it cannot re-parse\n in =%q\n out=%q\n err=%v", data, s1, err)
		}
		s2, err := doc2.WriteToBytes()
		if err != nil {
			t.Fatalf("re-serialise failed on etree's own output: %v (out=%q)", err, s1)
		}

		// RE-PARSEABILITY (round 2) + IDEMPOTENCE: s2 must be a fixed point of
		// serialise∘parse (f(f(f(x))) == f(f(x))). One extra round past s1 is allowed so the
		// handful of infoset-invariant spellings that settle on round 2 (empty CDATA — see the
		// header) do not false-positive, while a serialiser that never reaches a fixed point
		// (oscillation, or an infoset not stable under round-trip) still fails, as does any
		// output etree cannot re-parse.
		doc3 := etree.NewDocument()
		if err := doc3.ReadFromBytes(s2); err != nil {
			t.Fatalf("ROUND-TRIP: etree serialised output it cannot re-parse (round 2)\n in =%q\n out=%q\n err=%v", data, s2, err)
		}
		s3, err := doc3.WriteToBytes()
		if err != nil {
			t.Fatalf("re-serialise failed on etree's own output (round 2): %v (out=%q)", err, s2)
		}
		if !bytes.Equal(s2, s3) {
			t.Fatalf("IDEMPOTENCE: etree serialisation reaches no fixed point within two rounds\n s1=%q\n s2=%q\n s3=%q", s1, s2, s3)
		}
	})
}
