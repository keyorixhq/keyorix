package libconformance

// DF1 Oracle A — etree vs encoding/xml structural differential.
//
// Keyorix's SAML path reads the SAME response bytes twice: a namespace-strict
// encoding/xml walk (strictAssertionShape) decides which NameID is the identity, and
// crewjam/saml's parse (beevik/etree + goxmldsig, then encoding/xml.Unmarshal) extracts
// the NameID that is actually acted on (internal/saml/provider.go:260-281). A structural
// disagreement between etree and encoding/xml about the shape of a document is the raw
// material a signature-wrapping attack turns into "signature checked over element X,
// identity read from element Y". This oracle feeds one input to both libraries, builds a
// namespace-local-name canonical tree from each, and fails when the trees disagree in a
// way that is not a documented, intentional library difference.
//
// WHAT THIS ORACLE DOES NOT VERIFY:
//   - It compares ELEMENT names as {resolved-namespace-URI, local-name} (etree's
//     Element.NamespaceURI() resolves the in-scope xmlns; encoding/xml yields the URI in
//     Name.Space). ATTRIBUTE namespaces are compared by local name + value only, not by
//     resolved attribute-namespace URI — an attribute-namespace-only confusion with equal
//     local names and values is invisible here.
//   - It ignores inter-element whitespace-only text nodes (both libraries agree on them;
//     comparing them is pure noise).
//   - It does not assert anything about signatures, entity expansion (Go's decoder does
//     not expand external/DTD entities by construction), or re-serialisation (that is
//     FuzzEtreeRoundTripIdempotent's job).
//   - A document only one library accepts is NOT a finding here (return early); "one
//     parser is stricter" is expected and is not the dangerous shape — the dangerous
//     shape is both accept and disagree on structure.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// xmlNode is the canonical, namespace-local-name view both readings are reduced to.
// children are pointers so the encoding/xml builder can push a stack of live nodes
// without slice-growth aliasing bugs.
type xmlNode struct {
	name     string            // local element name
	attrs    map[string]string // attribute local-name -> value
	text     string            // concatenated direct character data, trimmed
	children []*xmlNode
}

func (n *xmlNode) canon() string {
	var b strings.Builder
	n.writeCanon(&b)
	return b.String()
}

func (n *xmlNode) writeCanon(b *strings.Builder) {
	b.WriteByte('<')
	b.WriteString(n.name)
	keys := make([]string, 0, len(n.attrs))
	for k := range n.attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, " %s=%q", k, n.attrs[k])
	}
	b.WriteByte('>')
	if t := strings.TrimSpace(n.text); t != "" {
		b.WriteString("#")
		b.WriteString(t)
	}
	for i := range n.children {
		n.children[i].writeCanon(b)
	}
	b.WriteString("</>")
}

// nsName renders a resolved element name as "uri|local" (empty uri => "|local").
func nsName(uri, local string) string { return uri + "|" + local }

// buildFromEtree walks an etree document into the canonical tree.
func buildFromEtree(el *etree.Element) *xmlNode {
	n := &xmlNode{name: nsName(el.NamespaceURI(), el.Tag), attrs: map[string]string{}}
	for _, a := range el.Attr {
		// skip xmlns declarations: they are namespace machinery, not data
		if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
			continue
		}
		n.attrs[a.Key] = a.Value
	}
	var text strings.Builder
	for _, child := range el.Child {
		switch c := child.(type) {
		case *etree.Element:
			n.children = append(n.children, buildFromEtree(c))
		case *etree.CharData:
			text.WriteString(c.Data)
		}
	}
	n.text = text.String()
	return n
}

// buildFromEncodingXML walks the same bytes via encoding/xml into the canonical tree.
// Returns (node, ok); ok=false means encoding/xml rejected the input.
func buildFromEncodingXML(data []byte) (*xmlNode, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var root *xmlNode
	rootCount := 0 // top-level elements seen
	stack := []*xmlNode{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xmlNode{name: nsName(t.Name.Space, t.Name.Local), attrs: map[string]string{}}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
					continue
				}
				n.attrs[a.Name.Local] = a.Value
			}
			if len(stack) == 0 {
				rootCount++
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				root = top
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(t)
			}
		}
	}
	// A well-formed XML document has EXACTLY ONE root element. encoding/xml's Token()
	// stream is lenient and happily tokenises `<A/><B/>` as two siblings, but Decode()
	// rejects trailing roots, and etree's doc.Root() returns only the FIRST. Rather than
	// pick a root and compare against etree's different pick (a harness artifact, not a
	// library semantic difference), treat a multi-root document as not-both-valid so the
	// oracle skips it — the comparison premise is one well-formed document.
	if root == nil || rootCount != 1 {
		return nil, false
	}
	return root, true
}

// xmlMismatch classifies a disagreement for allowlisting.
type xmlMismatch struct {
	key    string
	detail string
	a, b   string
}

// collectDeclaredNS gathers every namespace URI actually declared by an xmlns/xmlns:*
// attribute anywhere in the etree document. A prefix whose resolved "URI" is NOT in this
// set was never declared — it is a namespace-ill-formed document, and the two libraries
// handle that case differently (see the undeclared-prefix allowlist entry).
func collectDeclaredNS(el *etree.Element, out map[string]bool) {
	for _, a := range el.Attr {
		if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
			out[a.Value] = true
		}
	}
	for _, c := range el.ChildElements() {
		collectDeclaredNS(c, out)
	}
}

// splitNS splits an "uri|local" canonical name.
func splitNS(name string) (uri, local string) {
	if i := strings.IndexByte(name, '|'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// walkCompare walks the etree reading (a) and the encoding/xml reading (b) in parallel
// and returns the first precise mismatch, or nil if the trees are identical. declared is
// the set of namespace URIs the document actually declares.
func walkCompare(a, b *xmlNode, declared map[string]bool) *xmlMismatch {
	if a.name != b.name {
		au, al := splitNS(a.name)
		bu, bl := splitNS(b.name)
		switch {
		case al != bl:
			return &xmlMismatch{key: "local-name-differs", detail: "element local name differs", a: a.name, b: b.name}
		// undeclared prefix: encoding/xml keeps the literal prefix as the namespace,
		// etree resolves it to "" — the non-empty side's "URI" was never declared, so it
		// is a bare prefix token, not a real namespace. A DECLARED-vs-DECLARED mismatch
		// (both URIs in `declared`) falls through to the dangerous class below.
		case (au != "" && !declared[au]) || (bu != "" && !declared[bu]):
			return &xmlMismatch{key: "undeclared-prefix-ns", detail: "undeclared namespace prefix resolved differently", a: a.name, b: b.name}
		default:
			return &xmlMismatch{key: "declared-namespace-uri-differs", detail: "DECLARED namespace URI differs", a: a.name, b: b.name}
		}
	}
	if strings.TrimSpace(a.text) != strings.TrimSpace(b.text) {
		return &xmlMismatch{key: "text-differs", detail: "element text differs", a: a.text, b: b.text}
	}
	if len(a.attrs) != len(b.attrs) {
		return &xmlMismatch{key: "attr-count-differs", detail: "attribute count differs", a: a.canon(), b: b.canon()}
	}
	for k, av := range a.attrs {
		if bv, ok := b.attrs[k]; !ok || bv != av {
			return &xmlMismatch{key: "attr-value-differs", detail: "attribute " + k + " differs", a: a.canon(), b: b.canon()}
		}
	}
	if len(a.children) != len(b.children) {
		return &xmlMismatch{key: "child-count-differs", detail: "child element count differs", a: a.canon(), b: b.canon()}
	}
	for i := range a.children {
		if m := walkCompare(a.children[i], b.children[i], declared); m != nil {
			return m
		}
	}
	return nil
}

// xmlCompare is the pure oracle core: nil means "agree, or only one accepted".
func xmlCompare(data []byte) *xmlMismatch {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil
	}
	root := doc.Root()
	if root == nil {
		return nil // no element content (e.g. comment/PI only)
	}
	ex, ok := buildFromEncodingXML(data)
	if !ok {
		return nil // only etree accepted — "stricter parser" is expected, not dangerous here
	}
	declared := map[string]bool{"": true} // "" (no namespace) is always in scope
	collectDeclaredNS(root, declared)
	return walkCompare(buildFromEtree(root), ex, declared)
}

var xmlDiffAllow = func() *allowlist {
	return newAllowlist(
		expectedDiff{
			key: "undeclared-prefix-ns",
			reason: "Namespace-ill-formed document: a prefix (e.g. `x:` in `<x:a/>`) is used " +
				"with no in-scope xmlns:x declaration. encoding/xml keeps the literal prefix as the " +
				"Name.Space; beevik/etree's NamespaceURI() resolves it to \"\". Neither is 'wrong' — " +
				"XML Namespaces 1.0 makes this a (non-fatal for both libs) ill-formedness. A SAML / " +
				"XML-DSig document that reaches signature validation is already required to be " +
				"namespace-well-formed (mattermost/xml-roundtrip-validator + goxmldsig reject these " +
				"upstream), so the divergence is not reachable as a security decision. Recorded, not " +
				"a finding. RED-PROVEN by seed `<x:a/>`.",
		},
	)
}

var xmlSeeds = [][]byte{
	[]byte(`<a><b x="1">t</b><c/></a>`),
	[]byte(`<r xmlns:z="urn:z"><z:e a="1" b="2">x</z:e></r>`),
	[]byte(`<!-- c --><a>&amp;<![CDATA[<raw>]]></a>`),
	[]byte(`<Response><Assertion ID="_1"><Subject><NameID>alice</NameID></Subject></Assertion></Response>`),
	// signature-wrapping shaped seed: duplicate Assertion, foreign-namespace twin
	[]byte(`<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Assertion ID="_a"><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>` +
		`<Assertion ID="_a"><Subject><NameID>admin</NameID></Subject></Assertion></Response>`),
	[]byte(`<a xmlns="urn:d"><b>1</b></a>`),
	[]byte(`<a><b/><b/><b/></a>`),
	[]byte(`<x:a/>`),            // undeclared prefix: exercises the undeclared-prefix-ns allowlist entry
	[]byte(`<x:a><y:b/></x:a>`), // nested undeclared prefixes
}

func FuzzXMLEtreeVsEncodingXML(f *testing.F) {
	for _, s := range xmlSeeds {
		f.Add(s)
	}
	allow := xmlDiffAllow()
	f.Fuzz(func(t *testing.T, data []byte) {
		m := xmlCompare(data)
		if m == nil {
			return
		}
		if allow.allows(m.key) {
			return
		}
		t.Fatal(diffError("etree-vs-encoding/xml", m.detail+" (key="+m.key+")", m.a, m.b))
	})
}

func TestXMLDiffAllowlistNoDead(t *testing.T) {
	allow := xmlDiffAllow()
	for _, s := range xmlSeeds {
		if m := xmlCompare(s); m != nil {
			allow.allows(m.key)
		}
	}
	allow.assertNoDeadEntries(t)
}
