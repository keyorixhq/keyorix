package libconformance

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// TestXRVFindingXMLPrefixRebind pins finding LF1-XRV-xml-prefix-rebind, which
// FuzzXMLRoundtripValidatorDifferential's O1 skips as a known class. A document that
// rebinds the reserved xml prefix (xmlns:xml="urn:evil", forbidden by Namespaces in XML
// 1.0 §3) passes xrv.Validate and strict encoding/xml, yet encoding/xml resolves xml:b
// to the XML namespace while etree resolves it to urn:evil. This test goes red when the
// differential disappears (xrv, encoding/xml or etree starts rejecting or agreeing):
// then delete the known-class branch in checkXRVDifferential together with this test.
//
// What this does NOT verify: that the differential is exploitable through keyorix's
// SAML path (see the LF1 report's reachability trace; the signature covers the signed
// element's own declarations and encoding/xml never maps xml: onto a SAML namespace).
func TestXRVFindingXMLPrefixRebind(t *testing.T) {
	data := []byte(`<a xmlns:xml="urn:evil"><xml:b/></a>`)
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		t.Fatalf("xrv now rejects the xml-prefix rebind (%v): finding fixed, remove the known class", err)
	}
	if err := strictXMLDecode(data); err != nil {
		t.Fatalf("strict encoding/xml now rejects the xml-prefix rebind (%v): finding fixed, remove the known class", err)
	}
	std, err := encodingXMLView(data)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatalf("etree now rejects the xml-prefix rebind (%v): finding fixed, remove the known class", err)
	}
	if compareXMLViews(std, etreeView(doc, false)) == "" {
		t.Fatalf("encoding/xml and etree now agree on the xml-prefix rebind: finding fixed, remove the known class")
	}
	if got, want := std[1], "S "+xmlNamespaceURL+" b"; got != want {
		t.Fatalf("encoding/xml view %q, want %q", got, want)
	}
	if got, want := etreeView(doc, false)[1], "S urn:evil b"; got != want {
		t.Fatalf("etree view %q, want %q", got, want)
	}
}

// TestXRVDisagreementClassCensus logs how often each O2 class occurs over the seeds and
// the checked-in corpus, so a report can quote the distribution. It fails only on an
// unclassified pair, which the fuzz target also catches.
func TestXRVDisagreementClassCensus(t *testing.T) {
	inputs := make([][]byte, 0, len(xrvSeeds))
	for _, s := range xrvSeeds {
		inputs = append(inputs, []byte(s))
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "fuzz", "FuzzXMLRoundtripValidatorDifferential", "*"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if b, ok := corpusBytes(raw); ok {
			inputs = append(inputs, b)
		}
	}
	counts := map[string]int{}
	for _, in := range inputs {
		c := xrvStrictDisagreement(xrv.Validate(bytes.NewReader(in)), strictXMLDecode(in))
		if c == xrvClassUnclassified {
			t.Errorf("unclassified disagreement on %q", in)
		}
		counts[c]++
	}
	t.Logf("%d inputs, classes: %v", len(inputs), counts)
}

// corpusBytes decodes a one-[]byte go-fuzz corpus file ("go test fuzz v1" header, then
// one []byte("...") line).
func corpusBytes(raw []byte) ([]byte, bool) {
	lines := strings.SplitN(string(raw), "\n", 3)
	if len(lines) < 2 || lines[0] != "go test fuzz v1" {
		return nil, false
	}
	lit, ok := strings.CutPrefix(strings.TrimSpace(lines[1]), "[]byte(")
	if !ok {
		return nil, false
	}
	lit, ok = strings.CutSuffix(lit, ")")
	if !ok {
		return nil, false
	}
	s, err := strconv.Unquote(lit)
	if err != nil {
		return nil, false
	}
	return []byte(s), true
}
