package libconformance

import (
	"testing"

	"github.com/beevik/etree"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// FuzzEtreeParseComplexity is a cost-per-byte oracle over beevik/etree's XML
// parser, the DOM builder underneath Keyorix's SAML assertion path: the SAML
// ACS endpoint (server/http/handlers/saml.go CompleteSAML → internal/saml
// provider.go) parses the untrusted base64 SAMLResponse into an etree document
// for strict-shape validation and goxmldsig signature checking, under
// samlACSBodyLimit = 1 MiB (server/http/body_limits.go:20).
//
// XML is the canonical algorithmic-complexity surface: deep element nesting,
// enormous attribute counts, and huge sibling fan-out each turn a small input
// into a large in-memory tree. etree does NOT do DTD entity expansion, so the
// classic "billion laughs" entity bomb does not apply to it — but structural
// blow-up (1 MiB of `<a><a>...` nesting, or `<e a1="" a2="" ...>` with tens of
// thousands of attributes) still allocates a tree far larger than the bytes.
//
// Two proxies:
//   - allocated bytes per input byte (the tree's memory footprint), and
//   - a WORK counter = number of elements+attributes in the resulting tree,
//     per input byte, which catches structural amplification even when the
//     per-node allocation is small.
//
// What this oracle does NOT verify:
//   - Nothing about the parse result or any SAML/dsig security property (those
//     live in internal/saml's own fuzzers: FuzzSAMLXMLGrammar, FuzzParseResponse*).
//   - It does not exercise goxmldsig's canonicalization/transform cost, only the
//     etree parse that precedes it.
//   - The node-count work proxy is computed by walking the tree AFTER parse, so
//     it measures the tree etree built, not etree's internal transient work.
func FuzzEtreeParseComplexity(f *testing.F) {
	f.Add([]byte(`<r/>`))
	f.Add([]byte(`<r a="1" b="2" c="3"/>`))
	f.Add([]byte(`<a><b><c>x</c></b></a>`))
	f.Add([]byte(`<r><e/><e/><e/><e/><e/></r>`))         // wide siblings
	f.Add([]byte(`<a><a><a><a><a></a></a></a></a></a>`)) // deep nesting
	f.Add([]byte(``))

	// Budget for the 1 MiB SAML limit. An XML DOM is a few × the source bytes;
	// 256 B/byte slope + 2 MiB floor flags real super-linear growth. Node work:
	// at most ~1 node per 2 input bytes for the tightest legal markup (`<a>`),
	// so 1 node/byte + 4 Ki floor is a safe ceiling. Absolute: 1 MiB·256 = 256
	// MiB worst case, capped at 256 MiB.
	budget := complexity.Budget{
		MaxAllocBytesPerByte: 256,
		FloorBytes:           2 << 20,
		AbsMaxAllocBytes:     256 << 20,
		MaxWorkPerByte:       1,
		FloorWork:            4096,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		n := len(data)
		var doc *etree.Document
		work := func() uint64 {
			if doc == nil || doc.Root() == nil {
				return 0
			}
			return countNodes(&doc.Element)
		}
		c := complexity.MeasureWork(work, func() {
			doc = etree.NewDocument()
			_ = doc.ReadFromBytes(data) // result/err discarded; cost is the property
		})
		budget.Check(t.Fatalf, "etree.ReadFromBytes", n, c)
	})
}

// countNodes returns the number of elements plus attributes in the subtree.
func countNodes(e *etree.Element) uint64 {
	var n = 1 + uint64(len(e.Attr))
	for _, child := range e.ChildElements() {
		n += countNodes(child)
	}
	return n
}
