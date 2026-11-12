// Package grammar provides structure-aware input generation for the ASN.1 DER
// and XML parsers this repository drives (CMS/PKCS#7 via digitorus/pkcs7, X.509
// via crypto/x509 and encoding/asn1, SAML via crewjam/saml + beevik/etree +
// goxmldsig). It is imported only from _test.go fuzz files, and like
// internal/fuzzutil it imports no testing-only machinery, so it cannot leak a
// test dependency into a non-test build.
//
// The point of the package: byte-level fuzz mutation stalls at the first length
// or tag check (a random bit-flip in a DER length octet makes the whole
// structure unparseable, so the engine never gets past the envelope). Here the
// fuzzer's []byte is decoded into a *tree* plus a set of *mutation choices*
// (see decode.go), the tree is serialised to well-formed-by-construction DER/XML
// by the builders below, and the chosen mutations deliberately break specific
// invariants (indefinite length, non-minimal length, wrong tag class, …). The
// standard `go test -fuzz` engine then mutates the CHOICES, not the raw bytes —
// so its edits land on structural features instead of being rejected at octet 0.
//
// Nothing here asserts anything; it only *generates*. The oracles live in the
// fuzz targets that consume this package.
package grammar

import "encoding/binary"

// DER tag classes (the top two bits of the identifier octet).
const (
	ClassUniversal   uint8 = 0
	ClassApplication uint8 = 1
	ClassContext     uint8 = 2
	ClassPrivate     uint8 = 3
)

// DERMut is the per-node mutation set. The zero value produces strictly
// DER-correct encoding; each field, when set, breaks exactly one invariant so a
// parser's handling of that specific malformation is exercised. A fuzz target
// states in its own doc comment which of these it expects a correct parser to
// reject vs. tolerate.
type DERMut struct {
	// Indefinite uses BER indefinite-length form (identifier, 0x80, content,
	// end-of-contents 00 00) instead of a definite length. Only meaningful on a
	// constructed node; ignored on a primitive. DER forbids it outright, BER
	// permits it — the digitorus/pkcs7 BER→DER path is where this matters.
	Indefinite bool
	// NonMinimalLen, when >0, encodes the (definite) length in the long form
	// padded to this many octets even when the value fits in fewer — e.g. a
	// length of 5 written as 82 00 05. DER requires the minimal encoding.
	NonMinimalLen uint8
	// LenDelta, when !=0, is added to the length field actually written, so the
	// declared length disagrees with the real content length (overflow if >0,
	// under-run if <0). The content bytes themselves are unchanged.
	LenDelta int
	// WrongClass flips the identifier octet's class bits to (Class+1)%4, so e.g.
	// a UNIVERSAL SEQUENCE is tagged context-specific without changing anything
	// else.
	WrongClass bool
	// LongFormTag forces the high-tag-number (long) form for the tag number even
	// when it is < 31 and would fit in the identifier octet. DER requires the
	// short form when the number fits.
	LongFormTag bool
	// ExtraEOC appends a spurious end-of-contents (00 00) pair after this node's
	// definite-length content — trailing bytes at the point a parser thinks the
	// value ended.
	ExtraEOC bool
}

// DERNode is one TLV. A constructed node serialises its Children; a primitive
// node serialises Content verbatim. (A node may legally be constructed with no
// children — an empty SEQUENCE.)
type DERNode struct {
	Class       uint8
	Tag         uint32
	Constructed bool
	Content     []byte // used only when !Constructed
	Children    []*DERNode
	Mut         DERMut
}

// DERDoc is a whole document: a root node plus optional trailing bytes after it
// (a well-formed TLV followed by garbage — the "trailing data" malformation that
// a strict parser must reject and a lax one silently ignores).
type DERDoc struct {
	Root     *DERNode
	Trailing []byte
}

// Encode serialises the document to bytes.
func (d *DERDoc) Encode() []byte {
	if d == nil || d.Root == nil {
		return append([]byte(nil), d.trailing()...)
	}
	out := d.Root.Encode()
	return append(out, d.trailing()...)
}

func (d *DERDoc) trailing() []byte {
	if d == nil {
		return nil
	}
	return d.Trailing
}

// Encode serialises a single node (and, recursively, its subtree) to bytes.
func (n *DERNode) Encode() []byte {
	if n == nil {
		return nil
	}
	var content []byte
	if n.Constructed {
		for _, c := range n.Children {
			content = append(content, c.Encode()...)
		}
	} else {
		content = n.Content
	}

	out := n.identifier()

	if n.Constructed && n.Mut.Indefinite {
		// BER indefinite length: 0x80, content, end-of-contents.
		out = append(out, 0x80)
		out = append(out, content...)
		out = append(out, 0x00, 0x00)
		if n.Mut.ExtraEOC {
			out = append(out, 0x00, 0x00)
		}
		return out
	}

	declared := len(content) + n.Mut.LenDelta
	declared = max(declared, 0)
	out = append(out, encodeLen(declared, n.Mut.NonMinimalLen)...)
	out = append(out, content...)
	if n.Mut.ExtraEOC {
		out = append(out, 0x00, 0x00)
	}
	return out
}

// identifier builds the identifier octet(s) honouring the class/long-form
// mutations.
func (n *DERNode) identifier() []byte {
	class := n.Class & 0x03
	if n.Mut.WrongClass {
		class = (class + 1) & 0x03
	}
	var constructed uint8
	if n.Constructed {
		constructed = 1
	}
	lead := class<<6 | constructed<<5

	if n.Tag < 31 && !n.Mut.LongFormTag {
		return []byte{lead | byte(n.Tag)}
	}
	// High-tag-number form: low 5 bits set to 1, then base-128 big-endian with
	// the high bit set on all but the last octet.
	out := []byte{lead | 0x1f}
	return append(out, base128(n.Tag)...)
}

// base128 encodes a tag number in the DER high-tag-number continuation form.
func base128(v uint32) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var tmp [5]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte(v & 0x7f)
		v >>= 7
	}
	out := tmp[i:]
	// Set the continuation bit on every octet except the last.
	res := make([]byte, len(out))
	copy(res, out)
	for j := 0; j < len(res)-1; j++ {
		res[j] |= 0x80
	}
	return res
}

// encodeLen produces a definite-length encoding. pad==0 gives the minimal DER
// form; pad>0 forces the long form widened to pad octets (non-minimal, a BER/DER
// violation used as a mutation).
func encodeLen(n int, pad uint8) []byte {
	if pad == 0 {
		if n < 0x80 {
			return []byte{byte(n)}
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		i := 0
		for i < 8 && b[i] == 0 {
			i++
		}
		body := b[i:]
		return append([]byte{0x80 | byte(len(body))}, body...)
	}
	// Forced long form, pad octets wide (clamped to 1..8).
	width := min(max(int(pad), 1), 8)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	body := b[8-width:]
	return append([]byte{0x80 | byte(width)}, body...)
}

// Depth returns the maximum nesting depth of the tree (a leaf is depth 1). Used
// by callers that want to bound/report structural depth.
func (n *DERNode) Depth() int {
	if n == nil {
		return 0
	}
	max := 0
	for _, c := range n.Children {
		if d := c.Depth(); d > max {
			max = d
		}
	}
	return max + 1
}

// Count returns the total number of nodes in the subtree (including n).
func (n *DERNode) Count() int {
	if n == nil {
		return 0
	}
	total := 1
	for _, c := range n.Children {
		total += c.Count()
	}
	return total
}
