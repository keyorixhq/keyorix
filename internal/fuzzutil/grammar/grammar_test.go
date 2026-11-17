package grammar

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// TestDecodeDERTotal: Decode+Encode never panics and never errors for arbitrary
// bytes, including short/empty inputs.
func TestDecodeDERTotal(t *testing.T) {
	for _, in := range [][]byte{
		nil, {}, {0}, {1}, {1, 0, 0}, {0x01, 0xff, 0x02, 0xaa, 0x03},
		bytes.Repeat([]byte{0xff}, 64),
		bytes.Repeat([]byte{0x01, 0x80, 0x05}, 40),
	} {
		doc := DecodeDER(in)
		_ = doc.Encode() // must not panic
	}
}

// TestDERZeroMutationRoundTrips: a tree built with no mutations encodes to bytes
// that encoding/asn1 accepts and re-marshals identically (the "parse then marshal
// round-trip stable" property, on the clean side).
func TestDERZeroMutationRoundTrips(t *testing.T) {
	// SEQUENCE { INTEGER 1, INTEGER 258 } — hand-built, no mutations.
	root := &DERNode{Class: ClassUniversal, Tag: 16, Constructed: true, Children: []*DERNode{
		{Class: ClassUniversal, Tag: 2, Content: []byte{0x01}},
		{Class: ClassUniversal, Tag: 2, Content: []byte{0x01, 0x02}},
	}}
	der := (&DERDoc{Root: root}).Encode()

	type seq struct {
		A int
		B int
	}
	var out seq
	rest, err := asn1.Unmarshal(der, &out)
	if err != nil {
		t.Fatalf("asn1.Unmarshal rejected zero-mutation DER %x: %v", der, err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after zero-mutation DER: %x", rest)
	}
	if out.A != 1 || out.B != 258 {
		t.Fatalf("round-trip values wrong: %+v", out)
	}
	remarshalled, err := asn1.Marshal(out)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	if !bytes.Equal(der, remarshalled) {
		t.Fatalf("round-trip not stable:\n  built: %x\n  remar: %x", der, remarshalled)
	}
}

// TestDERDeepChain: the deep-chain opcode reaches real structural depth from a
// tiny input — the lever byte-level mutation cannot pull.
func TestDERDeepChain(t *testing.T) {
	// mode byte 0x01 selects deep chain; next two bytes set the depth.
	in := []byte{0x01, 0x10, 0x00}
	doc := DecodeDER(in)
	if got := doc.Root.Depth(); got < 1000 {
		t.Fatalf("deep chain only reached depth %d from a 3-byte input", got)
	}
	_ = doc.Encode() // large but must not panic
}

// TestDERMutationsChangeBytes: each mutation flag actually perturbs the encoding
// (so the fuzzer's choices are not inert).
func TestDERMutationsChangeBytes(t *testing.T) {
	base := &DERNode{Class: ClassUniversal, Tag: 16, Constructed: true, Children: []*DERNode{
		{Class: ClassUniversal, Tag: 2, Content: []byte{0x01}},
	}}
	ref := base.Encode()
	cases := map[string]DERMut{
		"indefinite":  {Indefinite: true},
		"nonminimal":  {NonMinimalLen: 3},
		"lenoverflow": {LenDelta: 5},
		"wrongclass":  {WrongClass: true},
		"longtag":     {LongFormTag: true},
		"extraeoc":    {ExtraEOC: true},
	}
	for name, m := range cases {
		n := *base
		n.Mut = m
		if bytes.Equal(n.Encode(), ref) {
			t.Fatalf("mutation %q did not change the encoding", name)
		}
	}
}

// TestDecodeXMLTotalAndWellFormed: Decode+Build never panics and, crucially,
// produces XML that a real parser (etree) accepts — the builder's framing is
// always well-formed even though the structure/namespaces may be adversarial.
func TestDecodeXMLTotalAndWellFormed(t *testing.T) {
	for _, in := range [][]byte{
		nil, {}, {0}, {2, 0, 0}, {1, 0x00, 0x10}, // deep chain
		bytes.Repeat([]byte{0x03, 0x41, 0x02}, 50),
		[]byte("random text not structured at all"),
	} {
		doc := DecodeXML(in)
		s := doc.Build()
		if s == "" {
			continue
		}
		// Strip a DOCTYPE if present: etree does not parse DOCTYPE internal
		// subsets, and well-formedness of the entity framing is checked
		// separately.
		body := s
		if i := strings.Index(body, "]>"); i >= 0 {
			body = body[i+2:]
		} else if strings.HasPrefix(body, "<!DOCTYPE") {
			if i := strings.Index(body, ">"); i >= 0 {
				body = body[i+1:]
			}
		}
		d := etree.NewDocument()
		if err := d.ReadFromString(body); err != nil {
			t.Fatalf("builder produced XML etree rejects: %v\n%q", err, body)
		}
	}
}

// TestXMLDeepChain: single-choice deep nesting for XML too.
func TestXMLDeepChain(t *testing.T) {
	in := []byte{0x00, 0x00, 0x00, 0x01, 0x10, 0x00} // mut, decl, doctype flags, mode=1, depth
	doc := DecodeXML(in)
	if got := doc.Root.Depth(); got < 1000 {
		t.Fatalf("XML deep chain only reached depth %d", got)
	}
}

// TestDecodeSAMLFragmentTotal: the SAML fragment decoder never panics and emits a
// shape in [0,4).
func TestDecodeSAMLFragmentTotal(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0}, {1, 2}, {2, 2, 3, 4}, {3, 3}, {4}, {5}, {6}, bytes.Repeat([]byte{0x7f}, 40)} {
		frag, shape := DecodeSAMLFragment(in)
		if shape >= 4 {
			t.Fatalf("shape out of range: %d", shape)
		}
		_ = frag
	}
}
