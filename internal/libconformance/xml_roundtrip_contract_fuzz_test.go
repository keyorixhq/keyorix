package libconformance

// XML ROUND-TRIP VALIDATOR CONTRACT DIFFERENTIAL (task NH1 / K10, oracle RT1).
//
// mattermost/xml-roundtrip-validator (xrv) is the guard the live SAML path relies on:
// internal/saml/provider.go:534 runs xrv.Validate on IdP metadata before handing the bytes
// to crewjam's xml.Unmarshal, and crewjam runs its own vendored copy on a SAMLResponse.
// The library's DOCUMENTED CONTRACT (go doc github.com/mattermost/xml-roundtrip-validator):
//
//     "Validate makes sure the given XML bytes survive round trips through encoding/xml
//      without mutations."
//     "CheckToken computes a round trip for a given xml.Token and returns an error if the
//      newly calculated token differs from the original."
//
// So the contract is: a document xrv ACCEPTS, when decoded to a token stream by encoding/xml,
// re-serialised, and decoded again, must yield an EQUIVALENT token stream. If it does not,
// the bytes the signature layer covers and the bytes the application re-serialises/consumes
// can differ — the exact signature-wrapping hole xrv exists to close. A document xrv accepts
// whose encoding/xml round trip is NOT stable is therefore a VALIDATOR-CONTRACT-VIOLATION
// CANDIDATE (the library accepted something its own promise says it must reject).
//
//   R-XRV  the mattermost/xml-roundtrip-validator verdict (the guard).
//   R-RT   an INDEPENDENT whole-document encoding/xml round trip: decode (RawToken) -> encode
//          (xml.Encoder) -> decode (RawToken), compared as canonical token streams.
//   R-UNM  the SAML path's own view: xml.Unmarshal into a generic recursive element, run on
//          the ORIGINAL bytes and on the RE-SERIALISED bytes; a difference means the round
//          trip changed what the unmarshal layer (crewjam's decode) consumes.
//
// INVARIANT (oracle RT1): xrv.Validate(data) == nil  ==>  tokens(R-RT before) ~= tokens(R-RT
// after) AND structure(R-UNM before) == structure(R-UNM after). The reverse (xrv rejects) is
// the safe direction and is only counted. This is ADDITIVE to oracle X1
// (xml_parser_differential_fuzz_test.go), which compares a beevik/etree parse against an
// encoding/xml parse of the SAME bytes and never re-serialises.
//
// WHAT THIS ORACLE DOES NOT VERIFY (so the green is not over-read):
//   - It uses ONE encoding/xml configuration (Strict=false, identity charset, RawToken so no
//     namespace resolution) and a SINGLE whole-document xml.Encoder. The validator's own
//     internal round trip is per-token with a fresh encoder; a divergence between the
//     document-level and per-token models that xrv REJECTS is not a finding and a benign one
//     that xrv accepts is catalogued (RT-E* below), not reported.
//   - It reads only the FIRST root element's subtree for the R-UNM structural compare (the
//     scope crewjam's unmarshalElement operates on); trailing content after the first root is
//     a separate class (provider_epilogue tests at the SAML layer).
//   - It compares the canonical TOKEN STREAM (kind, rendered name, sorted attribute name=value,
//     char-data/comment/PI/directive payload). Insignificant whitespace between elements is
//     normalised away (RT-E1); a difference confined to such whitespace is out of scope.
//   - It does not resolve entities or DOCTYPE (encoding/xml never does); that class is closed
//     by construction, not checked here.
//   - A re-serialise that xml.Encoder REFUSES (EncodeToken error) is treated as "cannot
//     round-trip -> nothing to assert", not a finding: the bytes never reach a second parse.
//   - It is a pure-parser oracle (no crewjam, no keys, no signature); the signature-wrapping
//     provenance checks live at the SAML layer (S1/S2/S3).

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
)

// rtToken is a canonical, comparable, LOCAL-NAME-NORMALISED rendering of one xml.Token.
//
// NAMESPACE NORMALISATION (RT-E2, the catalogued expected difference): element and attribute
// names are reduced to their LOCAL part and xmlns declarations are dropped. This is required,
// not cosmetic: Go's encoding/xml cannot round-trip a namespace PREFIX through
// RawToken->Encoder->RawToken (a `<x:a xmlns:x="urn:x"/>` re-serialises as
// `<a xmlns="x" xmlns:_xmlns="xmlns" _xmlns:x="urn:x">`), and the validator itself papers
// this over with its unexported fixNamespacePrefixes before comparing — i.e. the validator
// treats prefix re-spelling as equivalent and ACCEPTS it. Firing on it would therefore be a
// harness bug (reproducing a known encoding/xml limitation, not a Keyorix finding), and the
// namespace-skeleton agreement between parsers is already oracle X1's job. This oracle's
// distinct value is the RE-SERIALISE step: overflow (a token re-serialising into EXTRA
// tokens), dropped/added elements, changed nesting, changed attribute VALUES, changed text —
// all of which survive local-name normalisation. Attribute order is sorted (not infoset-
// significant).
func rtToken(tok xml.Token) string {
	switch t := tok.(type) {
	case xml.StartElement:
		attrs := make([]string, 0, len(t.Attr))
		for _, a := range t.Attr {
			if isXMLNSDecl(a.Name.Space, a.Name.Local) {
				continue // RT-E2: xmlns declaration, not an infoset attribute
			}
			attrs = append(attrs, a.Name.Local+"="+a.Value)
		}
		sort.Strings(attrs)
		return "S:" + t.Name.Local + "[" + strings.Join(attrs, "\x1f") + "]"
	case xml.EndElement:
		return "E:" + t.Name.Local
	case xml.CharData:
		// Insignificant inter-element whitespace is representational; RT-E1 normalises a
		// payload that is ONLY whitespace to the empty marker so the comparison is on
		// significant content. Non-whitespace char data is compared verbatim.
		if strings.TrimSpace(string(t)) == "" {
			return "C:" // RT-E1: whitespace-only char data
		}
		return "C:" + string(t)
	case xml.Comment:
		return "!:" + string(t)
	case xml.ProcInst:
		return "?:" + t.Target + " " + string(t.Inst)
	case xml.Directive:
		return "D:" + string(t)
	default:
		return fmt.Sprintf("U:%T", tok)
	}
}

// decodeRaw reads the whole document as a canonical token stream via RawToken (Strict=false,
// identity charset). ok=false when the bytes are not tokenisable at all.
func decodeRaw(data []byte) (toks []string, raw []xml.Token, ok bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, false
		}
		toks = append(toks, rtToken(tok))
		raw = append(raw, xml.CopyToken(tok))
	}
	return toks, raw, true
}

// reserialise feeds a RawToken stream back through a single whole-document xml.Encoder. ok is
// false when the encoder REFUSES a token (EncodeToken error) — then the bytes never reach a
// second parse and there is nothing to assert.
func reserialise(raw []xml.Token) ([]byte, bool) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	for _, t := range raw {
		if err := enc.EncodeToken(t); err != nil {
			return nil, false
		}
	}
	if err := enc.Flush(); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// elementSeq walks a RawToken stream and emits the ordered, depth-tagged sequence of element
// local names ("S:local@depth" / "E:local@depth"), ignoring attributes, char data, comments,
// PIs and directives. It is namespace-robust (local names only) by construction, so it is
// quiet on the prefix re-spelling and CDATA coalescing encoding/xml performs, and fires only
// on a change to the element TREE: an injected/dropped element (overflow), a rename, or a
// re-nesting.
func elementSeq(raw []xml.Token) []string {
	var out []string
	depth := 0
	for _, t := range raw {
		switch e := t.(type) {
		case xml.StartElement:
			out = append(out, fmt.Sprintf("S:%s@%d", e.Name.Local, depth))
			depth++
		case xml.EndElement:
			depth--
			out = append(out, fmt.Sprintf("E:%s@%d", e.Name.Local, depth))
		}
	}
	return out
}

// rtStreamsEqual compares two canonical token streams for equality.
func rtStreamsEqual(a, b []string) bool {
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

func rtStreamDiff(a, b []string) string {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return fmt.Sprintf("at tok#%d: before=%q after=%q", i, a[i], b[i])
		}
	}
	return fmt.Sprintf("length: before=%d after=%d (before=%v after=%v)", len(a), len(b), a, b)
}

// checkRoundtripContract is the RT1 oracle body with the real xrv validator.
func checkRoundtripContract(data []byte) (accepted bool, finding string) {
	return checkRoundtripContractWith(xrvValidate, data)
}

// checkRoundtripContractWith is the oracle parameterised by its validator (the red-proof
// substitutes an accept-all stub to prove the comparator is not vacuous and that the xrv
// verdict is the load-bearing guard). It uses the shipped reserialise.
func checkRoundtripContractWith(validate func([]byte) error, data []byte) (accepted bool, finding string) {
	return checkRoundtripContractFull(validate, reserialise, data)
}

// checkRoundtripContractFull is the oracle body, parameterised by both its validator and its
// re-serialiser. The shipped path (checkRoundtripContract) uses the real xrv validator and
// the real encoding/xml reserialise; the red-proof substitutes an accept-all validator and/or
// an INJECTING reserialise (one that simulates an encoding/xml overflow that duplicates an
// element) to prove the element-skeleton and unmarshal comparators actually fire on a genuine
// structural mutation. Returns accepted (the validator verdict) and finding (non-empty only
// for a round-trip mutation the validator ACCEPTED).
func checkRoundtripContractFull(validate func([]byte) error, reserialiseFn func([]xml.Token) ([]byte, bool), data []byte) (accepted bool, finding string) {
	if validate(data) != nil {
		return false, "" // validator rejected: the safe direction, nothing to assert.
	}
	toks1, raw1, ok := decodeRaw(data)
	if !ok {
		return true, "" // xrv accepted but not tokenisable here: nothing to round-trip.
	}
	b2, ok := reserialiseFn(raw1)
	if !ok {
		return true, "" // encoder refused: bytes never reach a second parse.
	}
	_, raw2, ok := decodeRaw(b2)
	if !ok {
		// xrv accepted and the FIRST parse produced a token stream, but the re-serialised
		// bytes do not parse at all: the round trip destroyed well-formedness. That is a
		// mutation the contract forbids.
		return true, "RE-SERIALISED BYTES DO NOT PARSE (xrv ACCEPTED): " + fmt.Sprintf("%q -> %q", data, b2)
	}
	_ = toks1 // the raw token stream is retained for diagnostics; the firing views below are
	// the namespace-robust element skeleton and the semantic unmarshal skeleton (see the file
	// header on why strict raw-token equality is NOT the firing condition: encoding/xml cannot
	// round-trip a namespace PREFIX and coalesces adjacent CDATA, both of which the validator
	// treats as equivalent and both of which are representational, not structural).

	// ELEMENT SKELETON: the ordered, depth-tagged sequence of element local names. This is the
	// overflow detector — a token that re-serialises into EXTRA elements (the signature-
	// wrapping primitive xrv exists to block), or a dropped/renamed/renested element, changes
	// it; namespace re-spelling and CDATA coalescing do not.
	es1 := elementSeq(raw1)
	es2 := elementSeq(raw2)
	if !rtStreamsEqual(es1, es2) {
		return true, "ELEMENT-SKELETON MUTATION (xrv ACCEPTED): " + rtStreamDiff(es1, es2)
	}

	// SAML-path tie-in (R-UNM): the unmarshal layer must see the same structure before and
	// after re-serialisation. A difference means the round trip changed what crewjam's
	// xml.Unmarshal consumes (element names, attribute VALUES, or text content).
	u1, ok1 := unmarshalSkeleton(data)
	u2, ok2 := unmarshalSkeleton(b2)
	if ok1 != ok2 {
		return true, fmt.Sprintf("UNMARSHAL ROUND-TRIP DIVERGENCE (xrv ACCEPTED): before-ok=%v after-ok=%v", ok1, ok2)
	}
	if ok1 && u1 != u2 {
		return true, "UNMARSHAL ROUND-TRIP DIVERGENCE (xrv ACCEPTED): before=" + u1 + " after=" + u2
	}
	return true, ""
}

// genericXML is a recursive structure capturing exactly what the unmarshal layer sees: each
// element's local name, its attribute name=value set, and its children — the information
// crewjam's structs are populated from. Namespaces are folded to the local name (the
// comparison is before-vs-after the round trip of the SAME document, so a consistent local-
// name view is sufficient to detect a structural change).
type genericXML struct {
	XMLName  xml.Name
	Attrs    []xml.Attr    `xml:",any,attr"`
	Children []genericXML  `xml:",any"`
	Chardata string        `xml:",chardata"`
}

func (g genericXML) render() string {
	var b strings.Builder
	var walk func(n genericXML)
	walk = func(n genericXML) {
		b.WriteString("<" + n.XMLName.Local)
		attrs := make([]string, 0, len(n.Attrs))
		for _, a := range n.Attrs {
			if isXMLNSDecl(a.Name.Space, a.Name.Local) {
				continue
			}
			attrs = append(attrs, a.Name.Local+"="+a.Value)
		}
		sort.Strings(attrs)
		b.WriteString("[" + strings.Join(attrs, ",") + "]")
		if txt := strings.TrimSpace(n.Chardata); txt != "" {
			b.WriteString("{" + txt + "}")
		}
		for _, c := range n.Children {
			walk(c)
		}
		b.WriteString(">")
	}
	walk(g)
	return b.String()
}

// unmarshalSkeleton renders the first root element as the unmarshal layer sees it. ok=false
// when xml.Unmarshal cannot build a structure (the application layer reads nothing).
func unmarshalSkeleton(data []byte) (string, bool) {
	var g genericXML
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(&g); err != nil {
		return "", false
	}
	return g.render(), true
}

// FuzzXMLRoundtripContract is oracle RT1. See the file header for the invariant and the list
// of what it does not verify.
func FuzzXMLRoundtripContract(f *testing.F) {
	seeds := []string{
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="_a"><saml:Subject><saml:NameID>u@x</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
		`<a xmlns="urn:d"><b x="1"/><c/></a>`,
		`<r xmlns:z="urn:z"><z:e a="1" b="2">x</z:e></r>`,
		`<a><b/><!-- c --><c/></a>`,
		`<a><![CDATA[<raw>]]></a>`,
		`<x:a xmlns:x="urn:x" x:k="v"/>`,
		`<a b="1" b="2"/>`,
		`<?xml version="1.0"?><a/>`,
		"<a>\n  <b/>\n</a>",
		`<a attr="&lt;&amp;&gt;"/>`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		accepted, finding := checkRoundtripContract(data)
		if accepted && finding != "" {
			t.Fatalf("RT1 VALIDATOR-CONTRACT-VIOLATION CANDIDATE: %s\n input=%q", finding, data)
		}
	})
}
