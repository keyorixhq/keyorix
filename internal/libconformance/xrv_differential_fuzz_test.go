package libconformance

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// FuzzXMLRoundtripValidatorDifferential pins what keyorix relies on in
// mattermost/xml-roundtrip-validator (xrv). internal/saml calls xrv.Validate on IdP
// metadata (parseIDPMetadata) and crewjam/saml calls it on every POSTed SAMLResponse
// before parsing; both inputs are attacker-influenced (the ACS endpoint is
// unauthenticated). xrv exists to stop documents that two XML readers see differently,
// so the oracles here compare the readers keyorix actually has on that path:
// encoding/xml (crewjam's xml.Unmarshal, parseIDPMetadata) and beevik/etree (goxmldsig's
// signature verification and crewjam's own tree walk).
//
//   - O1 VIEW AGREEMENT (security): when xrv accepts AND strict encoding/xml accepts,
//     etree must parse the bytes too, and both readers must build the same element tree:
//     namespace-resolved element names, effective attributes (resolved name, last value
//     wins, xmlns declarations excluded) and the merged character data between tags. A
//     difference is a parser differential that xrv let through.
//   - O2 ACCEPT/REJECT CLASSES: every disagreement between xrv's verdict and strict
//     encoding/xml's verdict on the same bytes must fall in a named class
//     (xrvStrictDisagreement). An unnamed class fails the target, so a new kind of
//     disagreement is triaged instead of passing silently. xrv rejecting what strict
//     encoding/xml accepts is only allowed as a round-trip rejection (xrv's job).
//   - O3 READER/API INDEPENDENCE (metamorphic): xrv's verdict is the same for a
//     bytes.Reader, a one-byte-at-a-time reader and a half reader, and
//     Validate(b) == nil exactly when ValidateAll(b) is empty.
//   - O4 BOUNDED WORK: Validate allocates at most xrvAllocPerByte bytes per input byte
//     plus a fixed 1 MiB (xrv is a single linear token pass; a superlinear blow-up on a
//     64 KiB input overshoots this by orders of magnitude).
//
// What this does NOT verify: comments, processing instructions and directives (neither
// reader's element view includes them, and c14n is goxmldsig's concern); whether the
// document is valid SAML; signature semantics (FuzzParseResponseXSW covers that through
// keyorix's own ParseResponse); non-UTF-8 charsets (strict encoding/xml without a
// CharsetReader rejects them, so O1 never sees them); inputs over 64 KiB; and wall-clock
// time (O4 counts bytes allocated, not time). O1 compares etree's NamespaceURI(), which
// cannot tell an unbound prefix from a prefix bound to "", so for a prefixed name that
// etree resolves to "" the encoding/xml side may be either "" or the literal prefix.
func FuzzXMLRoundtripValidatorDifferential(f *testing.F) {
	for _, s := range xrvSeeds {
		f.Add([]byte(s))
	}
	f.Add(bytes.Repeat([]byte("<a/>"), 16000)) // densest token shape: O4's worst legitimate case
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		checkXRVDifferential(t, data, xrv.Validate, xrv.ValidateAll)
	})
}

// xrvSeeds mixes SAML-shaped documents with the namespace-prefix cases from xrv's own
// advisories (the shapes the validator was written against).
var xrvSeeds = []string{
	`<Root></Root>`,
	`<x:Root xmlns:x="urn:x"><x:a y="1">t</x:a></x:Root>`,
	`<Root xmlns="urn:1" xmlns="urn:2"></Root>`,
	`<x:Root xmlns="urn:1" x:attr="y" x:attr2="z"/>`,
	`<Root><![CDATA[text "hello"]]>&amp;&#x41;</Root>`,
	`<!-- c --><?pi x?><Root/>`,
	`<x::Root/>`,
	`<Root><x::Element></::Element></Root>`,
	`<Root><Element ::attr="foo"></Element></Root>`,
	`<Root></x::Element></Root>`,
	`<Root xmlns:x="urn:a"><x:E xmlns:x="urn:b" x:a="1"/></Root>`,
	`<Root a="1" a="2"/>`,
	`<Root xmlns:p="urn:a" xmlns:q="urn:a" p:x="1" q:x="2"/>`,
	`<a xml:lang="en"><b xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:space="preserve"/></a>`,
	`<a xmlns:p="urn:a"><b xmlns:p=""><p:c/></b></a>`,
	`<Root>&foo;</Root>`,
	`<Root attr=unquoted/>`,
	`<a><b></a>`,
	`<?xml version="1.0" encoding="EUC-JP"?><Root/>`,
	`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r" Version="2.0"><saml:Issuer>https://idp</saml:Issuer><saml:Assertion ID="a"><saml:Subject><saml:NameID>u@x</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
	`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>`,
	`<a xmlns:xml="urn:evil"><xml:b xml:c="1"/></a>`,
	"<a>\r\n x \r y</a>",
	"<a>\xff</a>",
	`<a b="&#9;&#10;&#13;"/>`,
}

type xrvValidateFunc func(io.Reader) error
type xrvValidateAllFunc func(io.Reader) []error

// xrvAllocPerByte is O4's per-input-byte allocation ceiling. A Validate pass encodes and
// re-decodes every token through a fresh xml.Encoder (a 4 KiB bufio.Writer each), so a
// token-dense input legitimately allocates a few KiB per input byte: measured 2.5 KiB
// for 64 KB of `<a/>` (the densest shape found), 1.4 KiB for deep nesting, under 1 KiB
// for comments, PIs and namespaced elements, 6 bytes for entity-heavy text (xrv
// v0.1.0, Go 1.27). The ceiling leaves a 3x margin over the densest shape.
const xrvAllocPerByte = 8 << 10

func checkXRVDifferential(t *testing.T, data []byte, validate xrvValidateFunc, validateAll xrvValidateAllFunc) {
	t.Helper()

	// O4 bounded work (measured on the plain call, before anything else allocates).
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	xerr := validate(bytes.NewReader(data))
	runtime.ReadMemStats(&m1)
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > uint64(len(data))*xrvAllocPerByte+1<<20 {
		t.Fatalf("O4 BOUNDED-WORK: xrv.Validate allocated %d bytes for a %d-byte input\n in=%q", alloc, len(data), data)
	}
	accepted := xerr == nil

	// O3 reader and API independence.
	for name, r := range map[string]io.Reader{
		"one-byte": iotest.OneByteReader(bytes.NewReader(data)),
		"half":     iotest.HalfReader(bytes.NewReader(data)),
	} {
		if got := validate(r) == nil; got != accepted {
			t.Fatalf("O3 READER-DEPENDENT: Validate(bytes.Reader) accepted=%v, Validate(%s) accepted=%v\n in=%q\n err=%v", accepted, name, got, data, xerr)
		}
	}
	if all := validateAll(bytes.NewReader(data)); (len(all) == 0) != accepted {
		t.Fatalf("O3 API-INCONSISTENT: Validate accepted=%v but ValidateAll returned %d errors %v\n in=%q", accepted, len(all), all, data)
	}

	// O2 accept/reject classes against strict encoding/xml.
	strictErr := strictXMLDecode(data)
	if class := xrvStrictDisagreement(xerr, strictErr); class == xrvClassUnclassified {
		t.Fatalf("O2 UNCLASSIFIED DISAGREEMENT: xrv err=%v, strict encoding/xml err=%v\n in=%q", xerr, strictErr, data)
	}

	if !accepted || strictErr != nil {
		return
	}

	// O1 view agreement.
	std, err := encodingXMLView(data)
	if err != nil {
		t.Fatalf("O1 harness: strict decode accepted the bytes but the view walk failed: %v\n in=%q", err, data)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatalf("O1 VIEW-AGREEMENT: xrv and strict encoding/xml accept, etree rejects (%v)\n in=%q", err, data)
	}
	et := etreeView(doc, false)
	if diff := compareXMLViews(std, et); diff != "" {
		if xmlPrefixRebound(doc) && compareXMLViews(std, etreeView(doc, true)) == "" {
			return // known class: LF1-XRV-xml-prefix-rebind (see TestXRVFindingXMLPrefixRebind)
		}
		t.Fatalf("O1 VIEW-AGREEMENT: xrv accepted a document encoding/xml and etree read differently: %s\n in=%q\n encoding/xml=%q\n etree=%q", diff, data, std, et)
	}
}

// strictXMLDecode is what xml.Unmarshal's decoder does with the bytes: Strict, no
// CharsetReader, every token through Token (which matches end tags and resolves names).
func strictXMLDecode(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

const (
	xrvClassAgree        = "agree"
	xrvClassUnclassified = "UNCLASSIFIED"
)

// xrvLenientClasses names why xrv (RawToken, Strict=false, pass-through CharsetReader)
// can accept bytes strict encoding/xml rejects. None of them reaches keyorix's XML
// consumers: they all call strict encoding/xml or etree afterwards, which reject the
// same bytes. Each pattern matches the strict decoder's error text.
var xrvLenientClasses = []struct {
	name string
	re   *regexp.Regexp
}{
	{"unmatched-end-tag", regexp.MustCompile(`unexpected end element|element <[^>]*> closed by </|element <[^>]*> in space .* closed by`)},
	{"unclosed-at-eof", regexp.MustCompile(`unexpected EOF`)},
	{"charset-declared", regexp.MustCompile(`declared but Decoder.CharsetReader is nil|unsupported version`)},
	{"nonstrict-entity", regexp.MustCompile(`invalid character entity`)},
	{"nonstrict-attribute", regexp.MustCompile(`unquoted or missing attribute value|attribute name without = in element`)},
	{"nonstrict-syntax", regexp.MustCompile(`invalid XML name|expected element name after <|unexpected '\]\]>'|invalid sequence|invalid characters|in element|expected attribute name|expected comment|expected CDATA`)},
}

// xrvStrictDisagreement classifies the pair of verdicts. It returns xrvClassAgree when
// both verdicts match, a named class for a known disagreement, and
// xrvClassUnclassified otherwise.
func xrvStrictDisagreement(xerr, strictErr error) string {
	switch {
	case (xerr == nil) == (strictErr == nil):
		return xrvClassAgree
	case xerr != nil:
		// xrv rejects, strict accepts: only a round-trip rejection is xrv's job. A
		// non-round-trip error here would mean the lenient decoder failed where the
		// strict one succeeded.
		if _, ok := errors.AsType[xrv.XMLValidationError](xerr); ok {
			return "xrv-roundtrip-reject"
		}
		return xrvClassUnclassified
	default:
		msg := strictErr.Error()
		for _, c := range xrvLenientClasses {
			if c.re.MatchString(msg) {
				return c.name
			}
		}
		return xrvClassUnclassified
	}
}

const xmlNamespaceURL = "http://www.w3.org/XML/1998/namespace"

// A view is a flat event list: "S <uri> <local>", "A <uri> <local>=<value>" (effective
// attributes, sorted), "T <text>" (merged character data, never empty) and "E".
type xmlView []string

func viewAttrs(attrs map[[2]string]string) []string {
	out := make([]string, 0, len(attrs))
	for k, v := range attrs {
		out = append(out, fmt.Sprintf("A %s %s=%q", k[0], k[1], v))
	}
	slices.Sort(out)
	return out
}

func isXMLNSDecl(space, local string) bool {
	return space == "xmlns" || (space == "" && local == "xmlns")
}

func encodingXMLView(data []byte) (xmlView, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var v xmlView
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			v = append(v, "T "+text.String())
			text.Reset()
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			flush()
			return v, nil
		}
		if err != nil {
			return nil, err
		}
		switch tt := tok.(type) {
		case xml.StartElement:
			flush()
			v = append(v, fmt.Sprintf("S %s %s", tt.Name.Space, tt.Name.Local))
			attrs := map[[2]string]string{}
			for _, a := range tt.Attr {
				if isXMLNSDecl(a.Name.Space, a.Name.Local) {
					continue
				}
				attrs[[2]string{a.Name.Space, a.Name.Local}] = a.Value
			}
			v = append(v, viewAttrs(attrs)...)
		case xml.EndElement:
			flush()
			v = append(v, "E")
		case xml.CharData:
			text.Write(tt)
		}
	}
}

// etreeURI renders etree's resolution of a prefix. "?<prefix>" marks a prefixed name
// etree resolved to "" (unbound, or bound to ""), which compareXMLViews matches against
// either "" or the literal prefix on the encoding/xml side. specXML pins the "xml"
// prefix to its fixed namespace, as the Namespaces spec requires and encoding/xml does,
// whatever an xmlns:xml declaration says.
func etreeURI(prefix, uri string, specXML bool) string {
	switch {
	case prefix == "xml" && (uri == "" || specXML):
		return xmlNamespaceURL
	case prefix != "" && uri == "":
		return "?" + prefix
	}
	return uri
}

// xmlPrefixRebound reports whether any element declares xmlns:xml with a value other
// than the XML namespace (forbidden by Namespaces in XML 1.0 §3, accepted by xrv, strict
// encoding/xml and etree alike). encoding/xml ignores such a declaration; etree honours
// it, so the two readers then disagree on every xml:-prefixed name in scope.
func xmlPrefixRebound(doc *etree.Document) bool {
	var walk func(e *etree.Element) bool
	walk = func(e *etree.Element) bool {
		for _, a := range e.Attr {
			if a.Space == "xmlns" && a.Key == "xml" && a.Value != xmlNamespaceURL {
				return true
			}
		}
		return slices.ContainsFunc(e.ChildElements(), walk)
	}
	return slices.ContainsFunc(doc.ChildElements(), walk)
}

func etreeView(doc *etree.Document, specXML bool) xmlView {
	var v xmlView
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			v = append(v, "T "+text.String())
			text.Reset()
		}
	}
	var walk func(tokens []etree.Token)
	walk = func(tokens []etree.Token) {
		for _, tok := range tokens {
			switch tt := tok.(type) {
			case *etree.Element:
				flush()
				v = append(v, fmt.Sprintf("S %s %s", etreeURI(tt.Space, tt.NamespaceURI(), specXML), tt.Tag))
				attrs := map[[2]string]string{}
				for i := range tt.Attr {
					a := &tt.Attr[i]
					if isXMLNSDecl(a.Space, a.Key) {
						continue
					}
					attrs[[2]string{etreeURI(a.Space, a.NamespaceURI(), specXML), a.Key}] = a.Value
				}
				v = append(v, viewAttrs(attrs)...)
				walk(tt.Child)
				flush()
				v = append(v, "E")
			case *etree.CharData:
				text.WriteString(tt.Data)
			}
		}
	}
	walk(doc.Child)
	flush()
	return v
}

// compareXMLViews returns "" when the views agree, else a description of the first
// difference.
func compareXMLViews(std, et xmlView) string {
	if len(std) != len(et) {
		return fmt.Sprintf("event count %d (encoding/xml) vs %d (etree)", len(std), len(et))
	}
	for i := range std {
		if !xmlEventEqual(std[i], et[i]) {
			return fmt.Sprintf("event %d: %q (encoding/xml) vs %q (etree)", i, std[i], et[i])
		}
	}
	return ""
}

func xmlEventEqual(std, et string) bool {
	if std == et {
		return true
	}
	// Only S and A events carry a URI as their second field.
	sk, srest, _ := strings.Cut(std, " ")
	ek, erest, _ := strings.Cut(et, " ")
	if sk != ek || (sk != "S" && sk != "A") {
		return false
	}
	suri, sname, _ := strings.Cut(srest, " ")
	euri, ename, _ := strings.Cut(erest, " ")
	if sname != ename {
		return false
	}
	prefix, ambiguous := strings.CutPrefix(euri, "?")
	return ambiguous && (suri == "" || suri == prefix)
}
