package grammar

import "fmt"

// Bounds on what a decoded tree may grow to. These keep the BUILDER's own work
// bounded (a fuzzer must not be able to make Decode* itself OOM or hang before
// the target under test even runs) while still being large enough that the deep
// / wide structural shapes byte-level mutation cannot reach are reachable here in
// a single choice. maxChainDepth is deliberately in the thousands: a linear
// nesting chain that deep is the canonical thing a random DER/XML byte mutation
// essentially never produces but a one-field grammar choice produces trivially.
const (
	maxRecurseDepth = 8     // random (non-chain) recursion depth
	maxChildren     = 6     // children per node in random recursion
	maxNodes        = 4096  // total nodes in a random tree
	maxContentLen   = 4096  // primitive content length cap
	maxChainDepth   = 20000 // explicit deep-chain opcode cap
	maxSiblings     = 20000 // explicit wide-siblings opcode cap
)

// reader is a total, bounded cursor over the fuzzer's bytes. Every accessor is
// safe past end-of-input: it returns 0 / false / "" once the bytes run out, so a
// short input simply yields a small tree with no mutations rather than an error.
type reader struct {
	data  []byte
	pos   int
	nodes int
}

func (r *reader) byte() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func (r *reader) bool() bool { return r.byte()&1 == 1 }

func (r *reader) u16() uint16 {
	return uint16(r.byte())<<8 | uint16(r.byte())
}

// intn returns a value in [0,n) driven by the next two bytes (n<=65536).
func (r *reader) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.u16()) % n
}

// take returns up to max bytes of raw input as content.
func (r *reader) take(max int) []byte {
	if max <= 0 || r.pos >= len(r.data) {
		return nil
	}
	n := int(r.byte()) % (max + 1)
	if r.pos+n > len(r.data) {
		n = len(r.data) - r.pos
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return append([]byte(nil), out...)
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

// DecodeDER turns the fuzzer's bytes into a DER document. The first control byte
// selects the top-level shape; a "deep chain" or "wide siblings" shape gives the
// fuzzer single-choice access to structural depth/breadth that byte-level
// mutation of a DER blob cannot reach.
func DecodeDER(data []byte) *DERDoc {
	r := &reader{data: data}
	doc := &DERDoc{}

	mode := r.byte()
	switch mode & 0x03 {
	case 1:
		// Deep nesting chain: depth from the next two bytes, wrapping one inner
		// primitive. This is the structural lever — a definite-length, well-formed
		// chain of N constructed SEQUENCEs.
		depth := r.intn(maxChainDepth) + 1
		doc.Root = derDeepChain(depth, r.derPrimitive())
	case 2:
		// Wide siblings: one SEQUENCE with many identical primitive children.
		n := r.intn(maxSiblings) + 1
		root := &DERNode{Class: ClassUniversal, Tag: 16, Constructed: true}
		child := r.derPrimitive()
		for range n {
			root.Children = append(root.Children, child)
		}
		doc.Root = root
	default:
		doc.Root = r.derNode(0)
	}
	applyDERMut(&doc.Root.Mut, r)

	// Optional trailing bytes.
	if r.bool() {
		doc.Trailing = r.take(16)
	}
	return doc
}

func (r *reader) derPrimitive() *DERNode {
	r.nodes++
	return &DERNode{
		Class:   r.byte() & 0x03,
		Tag:     uint32(r.byte() % 31),
		Content: r.take(maxContentLen),
	}
}

func (r *reader) derNode(depth int) *DERNode {
	r.nodes++
	n := &DERNode{Class: r.byte() & 0x03}
	tagByte := r.byte()
	n.Tag = uint32(tagByte)
	n.Constructed = tagByte&0x20 != 0
	applyDERMut(&n.Mut, r)

	if n.Constructed && depth < maxRecurseDepth && r.nodes < maxNodes {
		count := int(r.byte()) % (maxChildren + 1)
		for range count {
			if r.nodes >= maxNodes {
				break
			}
			n.Children = append(n.Children, r.derNode(depth+1))
		}
	} else {
		n.Constructed = false
		n.Content = r.take(maxContentLen)
	}
	return n
}

// applyDERMut reads one mutation-choice byte and one length-width byte and sets
// the node's mutation flags. Each bit maps to one structural malformation.
func applyDERMut(m *DERMut, r *reader) {
	c := r.byte()
	m.Indefinite = c&0x01 != 0
	m.WrongClass = c&0x02 != 0
	m.LongFormTag = c&0x04 != 0
	m.ExtraEOC = c&0x08 != 0
	if c&0x10 != 0 {
		m.NonMinimalLen = (r.byte() % 7) + 2 // 2..8 octets
	}
	switch c & 0x60 {
	case 0x20:
		m.LenDelta = 1 + int(r.byte()) // overflow: declare more than present
	case 0x40:
		m.LenDelta = -(1 + int(r.byte())) // under-run
	}
}

// derDeepChain builds a linear chain of `depth` constructed SEQUENCE nodes with
// `inner` at the bottom. Iterative (not recursive) so building the chain itself
// cannot overflow the builder's own stack.
func derDeepChain(depth int, inner *DERNode) *DERNode {
	node := inner
	if node == nil {
		node = &DERNode{Class: ClassUniversal, Tag: 2, Content: []byte{0x01}} // INTEGER 1
	}
	for range depth {
		node = &DERNode{Class: ClassUniversal, Tag: 16, Constructed: true, Children: []*DERNode{node}}
	}
	return node
}

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

// DecodeXML turns the fuzzer's bytes into an XML document. As with DER, the first
// control byte selects a top-level shape, including single-choice deep nesting
// and wide-sibling shapes.
func DecodeXML(data []byte) *XMLDoc {
	r := &reader{data: data}
	doc := &XMLDoc{}
	applyXMLMut(&doc.Mut, r)
	doc.Decl = r.bool()

	// Optional DOCTYPE with internal entities (entity / DOCTYPE shapes).
	if r.bool() {
		doc.Doctype = r.doctype()
	}

	mode := r.byte()
	switch mode & 0x03 {
	case 1:
		depth := r.intn(maxChainDepth) + 1
		doc.Root = xmlDeepChain(depth, r)
	case 2:
		n := r.intn(maxSiblings) + 1
		root := &XMLNode{Local: "r"}
		for range n {
			root.Children = append(root.Children, XMLItem{Kind: XMLElem, Elem: &XMLNode{Local: "e"}})
		}
		doc.Root = root
	default:
		doc.Root = r.xmlNode(0)
	}
	if doc.Root == nil {
		doc.Root = &XMLNode{Local: "r"}
	}
	return doc
}

func (r *reader) doctype() Doctype {
	dt := Doctype{Name: "r", RootName: "r"}
	n := r.intn(8)
	// Chain the entities so each references the previous — the billion-laughs
	// SHAPE. The builder never expands them; a parser that does is the finding.
	for i := range n {
		val := "x"
		if i > 0 {
			prev := fmt.Sprintf("e%d", i-1)
			val = fmt.Sprintf("&%s;&%s;", prev, prev)
		}
		dt.Entities = append(dt.Entities, XMLEntity{Name: fmt.Sprintf("e%d", i), Value: val})
	}
	return dt
}

func (r *reader) xmlNode(depth int) *XMLNode {
	r.nodes++
	n := &XMLNode{Local: xmlName(r.byte())}
	if r.bool() {
		n.Prefix = xmlName(r.byte())
		n.NS = append(n.NS, XMLNS{Prefix: n.Prefix, URI: fmt.Sprintf("urn:ns:%d", r.byte())})
	}
	// Attributes.
	for i, na := 0, r.intn(6); i < na; i++ {
		n.Attrs = append(n.Attrs, XMLAttr{Name: xmlName(r.byte()) + fmt.Sprintf("%d", i), Value: string(r.take(32))})
	}
	n.ReorderAttrs = r.bool()
	if r.bool() {
		n.DupID = "dup"
	}

	if depth < maxRecurseDepth && r.nodes < maxNodes {
		for i, nc := 0, r.intn(maxChildren+1); i < nc; i++ {
			if r.nodes >= maxNodes {
				break
			}
			switch r.byte() & 0x03 {
			case 0:
				n.Children = append(n.Children, XMLItem{Kind: XMLElem, Elem: r.xmlNode(depth + 1)})
			case 1:
				n.Children = append(n.Children, XMLItem{Kind: XMLText, Text: string(r.take(32))})
			case 2:
				n.Children = append(n.Children, XMLItem{Kind: XMLComment, Text: string(r.take(32))})
			case 3:
				n.Children = append(n.Children, XMLItem{Kind: XMLCData, Text: string(r.take(32))})
			}
		}
	}
	return n
}

func applyXMLMut(m *XMLMut, r *reader) {
	c := r.byte()
	m.ExtraWhitespace = c&0x01 != 0
	m.SplitText = c&0x02 != 0
	if c&0x04 != 0 {
		m.RebindPrefix = true
		m.RebindTo = xmlName(r.byte())
	}
}

func xmlDeepChain(depth int, r *reader) *XMLNode {
	// Build bottom-up iteratively.
	node := &XMLNode{Local: "leaf"}
	for i := range depth {
		parent := &XMLNode{Local: fmt.Sprintf("e%d", i%1000)}
		// Each level optionally declares a unique, unused prefix — the O(depth)
		// ancestor-walk trap the SAML transitive target documents.
		parent.NS = append(parent.NS, XMLNS{Prefix: fmt.Sprintf("p%d", i), URI: fmt.Sprintf("urn:ns:%d", i)})
		parent.Children = []XMLItem{{Kind: XMLElem, Elem: node}}
		node = parent
	}
	return node
}

// xmlName maps a byte to a short, always-valid XML name character set so the
// builder never emits a malformed tag/attr name from fuzzer input.
func xmlName(b byte) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	return string(alpha[int(b)%len(alpha)])
}
