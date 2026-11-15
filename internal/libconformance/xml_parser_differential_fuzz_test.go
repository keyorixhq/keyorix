package libconformance

// XML PARSER-DIFFERENTIAL (task SX1, oracle X1). The highest-value XML bug class for a Go
// SSO stack is "the same bytes read differently by two XML layers", because crewjam/saml
// verifies a signature over an element tree built by ONE layer (beevik/etree, driving
// goxmldsig) and then extracts the Go structs it trusts with a SECOND, independent decode
// (encoding/xml, via crewjam's unmarshalElement). If those two layers resolve the element
// skeleton — qualified element names, their nesting, and each element's resolved attribute
// names — differently, the signature can cover one element while the application consumes
// another. mattermost/xml-roundtrip-validator exists specifically to close that gap, and the
// live Keyorix path runs it: internal/saml/provider.go:534 calls xrv.Validate on the decoded
// SAMLResponse before handing it to crewjam, and crewjam then runs its own vendored copy
// (crewjam/saml/internal/xmlroundtrip) too.
//
// This harness is the arbiter test for that guarantee, at the pure-parser layer (no crewjam,
// no keys), so it is additive to — not a re-do of — the signature-wrapping differential
// (oracles S1/S2/S3 on branch fuzz/saml-differential, which drive the whole ParseResponse).
//
//   R-ETREE   beevik/etree's resolved element tree (the signature layer's view).
//   R-XML     an INDEPENDENT encoding/xml token walk with Decoder.Token() namespace
//             resolution (the unmarshal layer's view).
//   R-XRV     the mattermost/xml-roundtrip-validator verdict (the guard Keyorix relies on).
//
// INVARIANT (oracle X1): xrv.Validate(data) == nil  ==>  skeleton(R-ETREE) == skeleton(R-XML).
// A document the validator ACCEPTS whose two parser views disagree on the element skeleton is
// a VALIDATOR-BYPASS CANDIDATE. The reverse (xrv rejects) is the safe direction and is only
// counted. Every KNOWN benign divergence class is named in EXPECTED-DIFFERENCES-xml-parser-
// differential.md and normalized away below, so that only a NEW class fails.
//
// WHAT THIS ORACLE DOES NOT VERIFY (stated so the green is not over-read):
//   - It compares the element SKELETON (ordered resolved qualified element names + depth, and
//     per-element resolved attribute name set). It does NOT compare text content, CDATA,
//     comments, processing instructions, attribute VALUES, or attribute order — those are
//     either representational noise at this layer or are covered by the SAML-layer provenance
//     oracles S1/S2. A divergence confined to text/comments is out of this oracle's scope.
//   - It uses ONE fixed encoding/xml configuration (Strict=false, identity charset). A
//     different configuration (e.g. crewjam's Strict-default unmarshal) could decode
//     differently; that is a separate oracle, not asserted here.
//   - It does not resolve or expand entities or DOCTYPE (Go's encoding/xml never does), so the
//     entity-expansion class is closed by construction, not checked here.
//   - xrv ACCEPTING is necessary for a failure; a divergence xrv REJECTS is not a finding
//     (the guard did its job) and is not reported.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// skelNode is one element in the document-order skeleton: its depth, its resolved
// "{namespace-uri}local" qualified name, and its resolved attribute names (xmlns
// declarations excluded — a namespace declaration is not an infoset attribute). Attribute
// VALUES are deliberately not part of the skeleton (see "does not verify" above).
type skelNode struct {
	depth int
	name  string
	attrs string // sorted, "\x1f"-joined resolved attribute qualified names
}

func (n skelNode) String() string {
	return fmt.Sprintf("%d:%s[%s]", n.depth, n.name, n.attrs)
}

// qname renders a resolved qualified name. An empty namespace URI yields the bare local
// name, matching how both etree (NamespaceURI()=="") and encoding/xml (Name.Space=="")
// present a name in no namespace.
func qname(space, local string) string {
	if space == "" {
		return local
	}
	return "{" + space + "}" + local
}

// isXMLNSDecl reports whether an encoding/xml attribute name is a namespace declaration
// (xmlns or xmlns:prefix) rather than a real attribute. After Decoder.Token() resolution the
// declaration surfaces either as Space=="xmlns" (for xmlns:p) or as the bare Local=="xmlns".
func isXMLNSDecl(space, local string) bool {
	return space == "xmlns" || (space == "" && local == "xmlns") || space == "http://www.w3.org/2000/xmlns/"
}

// etreeSkeleton builds R-ETREE: the resolved element skeleton as beevik/etree sees it.
func etreeSkeleton(data []byte) ([]skelNode, bool) {
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = true
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, false
	}
	root := doc.Root()
	if root == nil {
		return nil, false
	}
	var out []skelNode
	var walk func(el *etree.Element, depth int)
	walk = func(el *etree.Element, depth int) {
		var names []string
		for _, a := range el.Attr {
			// etree represents an xmlns declaration as an attr with Space=="xmlns" or the
			// bare key "xmlns"; exclude it as above.
			if isXMLNSDecl(a.Space, a.Key) {
				continue
			}
			names = append(names, qname(a.NamespaceURI(), a.Key))
		}
		sort.Strings(names)
		out = append(out, skelNode{depth: depth, name: qname(el.NamespaceURI(), el.Tag), attrs: strings.Join(names, "\x1f")})
		for _, child := range el.ChildElements() {
			walk(child, depth+1)
		}
	}
	walk(root, 0)
	return out, true
}

// xmlSkeleton builds R-XML: the resolved element skeleton from an INDEPENDENT encoding/xml
// token walk. Decoder.Token() (not RawToken) resolves namespace prefixes to URIs, so this is
// the view the unmarshal layer sees. Strict=false + identity charset mirrors how the
// permissive SAML decoders accept input, so a divergence surfaces instead of being hidden by
// a parse rejection on one side only.
//
// Like etree's Root() and crewjam's unmarshalElement (which operate on a SINGLE element),
// this reads exactly the first root element's subtree and STOPS: trailing content after the
// first root is a separate class (epilogue/trailing-content, covered at the SAML layer by
// internal/saml's provider_epilogue tests), not an in-tree signature-vs-application
// confusion, so comparing it here would be comparing two different scopes. allRoots=false is
// the shipped, faithful model; the test-only full walk (allRoots=true) exists for the
// red-proof, to show the comparator fires on a genuine multi-element structural difference.
func xmlSkeleton(data []byte) ([]skelNode, bool) { return xmlSkeletonTokens(data, false) }

func xmlSkeletonTokens(data []byte, allRoots bool) ([]skelNode, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var out []skelNode
	depth := 0
	rootClosed := false
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
			if rootClosed && !allRoots {
				return out, true // second top-level root: trailing content, not compared
			}
			var names []string
			for _, a := range t.Attr {
				if isXMLNSDecl(a.Name.Space, a.Name.Local) {
					continue
				}
				names = append(names, qname(a.Name.Space, a.Name.Local))
			}
			sort.Strings(names)
			out = append(out, skelNode{depth: depth, name: qname(t.Name.Space, t.Name.Local), attrs: strings.Join(names, "\x1f")})
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 {
				rootClosed = true
			}
		}
	}
	return out, true
}

func skeletonsEqual(a, b []skelNode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// skeletonDiff returns a short human-readable description of the first divergence, for a
// finding report.
func skeletonDiff(a, b []skelNode) string {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return fmt.Sprintf("at #%d: etree=%s xml=%s", i, a[i], b[i])
		}
	}
	return fmt.Sprintf("length: etree=%d xml=%d (etree=%v xml=%v)", len(a), len(b), a, b)
}

// xmlReservedNS is the namespace URI the reserved "xml:" prefix is always bound to.
// encoding/xml's Decoder.Token() attaches it; beevik/etree does not. (Expected difference N2.)
const xmlReservedNS = "http://www.w3.org/XML/1998/namespace"

// normalizeName applies the catalogued, benign representational transforms to a single
// "{uri}local" (or bare "local") name so the two parsers' conventions coincide. Each transform
// is one EXPECTED-DIFFERENCE row (see EXPECTED-DIFFERENCES-xml-parser-differential.md); the
// function IS the machine-checked form of that catalogue. A difference NOT removed here
// survives to the failing assertion, so a genuinely new class still fires.
//
//	N1 undeclared-prefix: encoding/xml leaves an undeclared prefix verbatim in Name.Space
//	  ("a" for <a:x> with no xmlns:a); etree drops it to "". Such a prefix is not a real
//	  namespace URI (no "://", not "urn:"). A signed element can never carry one past
//	  goxmldsig's C14N (etreeutils errors on an unresolvable prefix), so this is malformed-
//	  input representation, not signature-vs-application confusion. Drop the "{pfx}" wrapper.
//	N2 reserved xml: namespace — drop the "{http://www.w3.org/XML/1998/namespace}" wrapper
//	  (both layers agree the attribute/element exists; they differ only on attaching the
//	  always-bound reserved URI).
func normalizeName(s string) string {
	for {
		open := strings.IndexByte(s, '{')
		if open < 0 {
			return s
		}
		closeIdx := strings.IndexByte(s[open:], '}')
		if closeIdx < 0 {
			return s
		}
		closeIdx += open
		uri := s[open+1 : closeIdx]
		isReal := strings.Contains(uri, "://") || strings.HasPrefix(uri, "urn:")
		if uri == xmlReservedNS { // N2: reserved xml: prefix
			s = s[:open] + s[closeIdx+1:]
			continue
		}
		if !isReal { // N1: unresolved/undeclared prefix
			s = s[:open] + s[closeIdx+1:]
			continue
		}
		// Real URI: keep this wrapper, advance past it.
		rest := normalizeName(s[closeIdx+1:])
		return s[:closeIdx+1] + rest
	}
}

// normalizeAttrs normalizes each "\x1f"-joined resolved attribute name (via normalizeName)
// and de-duplicates identical names.
//
//	N3 duplicate-attribute-name: a document with a repeated attribute name (<a b="1" b="2"/>)
//	  is not well-formed XML. etree keeps one; encoding/xml (Strict=false) keeps both. Both
//	  see the malformedness; collapsing to the set of distinct names removes only that
//	  representational count difference, not any element-identity signal.
func normalizeAttrs(attrs string) string {
	if attrs == "" {
		return ""
	}
	parts := strings.Split(attrs, "\x1f")
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		n := normalizeName(p)
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, "\x1f")
}

// normalizeSkeleton applies N1/N2/N3 to every node, yielding the form in which the two
// parsers are expected to agree. Any residual inequality is a real finding.
func normalizeSkeleton(sk []skelNode) []skelNode {
	out := make([]skelNode, len(sk))
	for i, n := range sk {
		out[i] = skelNode{depth: n.depth, name: normalizeName(n.name), attrs: normalizeAttrs(n.attrs)}
	}
	return out
}

// xrvValidate is the real validator the fuzz target uses. The red-proof tests substitute an
// accept-all stub to prove the comparator fires on a genuine skeleton divergence and that the
// xrv verdict is the load-bearing guard that keeps it from firing on the live path.
func xrvValidate(data []byte) error { return xrv.Validate(bytes.NewReader(data)) }

// checkParserDifferential is the oracle body with the real xrv validator.
func checkParserDifferential(data []byte) (accepted bool, finding string) {
	return checkParserDifferentialWith(xrvValidate, data)
}

// checkParserDifferentialWith is the oracle body parameterised by its round-trip validator.
// It returns accepted (the validator verdict) and finding (empty when there is nothing to
// report, an "E…"-catalogued expected difference is normalised away, or the validator
// rejected; non-empty for a genuine skeleton divergence the validator ACCEPTED).
func checkParserDifferentialWith(validate func([]byte) error, data []byte) (accepted bool, finding string) {
	if validate(data) != nil {
		return false, "" // validator rejected: the safe direction, nothing to assert.
	}
	etreeSk, ok1 := etreeSkeleton(data)
	xmlSk, ok2 := xmlSkeleton(data)
	if !ok1 || !ok2 {
		// xrv accepted but at least one parser built no tree. The only SUSPICIOUS direction is
		// etree (the signature layer) building a real element tree while the encoding/xml walk
		// (the application layer) builds none: bytes the signed tree is derived from that the
		// unmarshal layer cannot read. The REVERSE — encoding/xml + xrv accept (and build a
		// tree from) bytes etree rejects — is etree being STRICTER than the round-trip check
		// (EXPECTED DIFFERENCE E4). etree is crewjam's first gate (ParseResponse decodes with
		// etree before any unmarshal), so etree-stricter is the safe direction and is not a
		// finding. A document with no elements on either side (empty, whitespace/comment/PI-
		// only) is agreement, not a divergence.
		if ok1 && !ok2 && len(etreeSk) > 0 {
			return true, fmt.Sprintf("one-sided parse: etree built %d elements, encoding/xml built none", len(etreeSk))
		}
		return true, ""
	}
	nEtree, nXML := normalizeSkeleton(etreeSk), normalizeSkeleton(xmlSk)
	if skeletonsEqual(nEtree, nXML) {
		return true, "" // equal, or differ only by a catalogued (N1/N2/N3) expected difference
	}
	return true, "SKELETON DIVERGENCE (xrv ACCEPTED): " + skeletonDiff(nEtree, nXML)
}

// FuzzXMLParserDifferential is oracle X1. See the file header for the invariant and the list
// of what it does not verify.
func FuzzXMLParserDifferential(f *testing.F) {
	seeds := []string{
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="_a"><saml:Subject><saml:NameID>u@x</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
		`<a xmlns="urn:d"><b x="1"/><c/></a>`,
		`<r xmlns:z="urn:z"><z:e a="1" b="2">x</z:e></r>`,
		`<a><b/><!-- c --><c/></a>`,
		`<a xmlns:p="urn:p" xmlns:q="urn:p"><p:x/><q:x/></a>`, // two prefixes, same URI
		`<a><![CDATA[<raw>]]></a>`,
		`<x:a xmlns:x="urn:x" x:k="v"/>`,
		`<a b="1" b="2"/>`, // duplicate attribute (encoding/xml Strict=false tolerates)
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound the harness's own work; a pathological input that makes one PARSER itself hang
		// is a different oracle (the per-library bounded-work fuzzers) — here we cap input size
		// so this target stays linear and focused on the differential.
		if len(data) > 1<<20 {
			return
		}
		accepted, finding := checkParserDifferential(data)
		if accepted && strings.HasPrefix(finding, "SKELETON DIVERGENCE") {
			t.Fatalf("X1 VALIDATOR-BYPASS CANDIDATE: %s\n input=%q", finding, data)
		}
		if accepted && strings.HasPrefix(finding, "one-sided parse") {
			t.Fatalf("X1 ONE-SIDED PARSE (xrv ACCEPTED): %s\n input=%q", finding, data)
		}
	})
}
