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
//   - IDEMPOTENCE: after one normalisation round, serialisation is a fixed point —
//     serialise(parse(serialise(parse(x)))) == serialise(parse(x)). Canonicalisation that is
//     not idempotent means the "same" document has two byte forms, the seam XSW attacks slip
//     through.
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

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(data); err != nil {
			return // only well-formed inputs exercise the round-trip
		}
		s1, err := doc.WriteToBytes()
		if err != nil {
			return
		}

		doc2 := etree.NewDocument()
		if err := doc2.ReadFromBytes(s1); err != nil {
			t.Fatalf("ROUND-TRIP: etree serialised output it cannot re-parse\n in =%q\n out=%q\n err=%v", data, s1, err)
		}
		s2, err := doc2.WriteToBytes()
		if err != nil {
			t.Fatalf("re-serialise failed on etree's own output: %v (out=%q)", err, s1)
		}
		if !bytes.Equal(s1, s2) {
			t.Fatalf("IDEMPOTENCE: etree serialisation is not a fixed point\n s1=%q\n s2=%q", s1, s2)
		}
	})
}
