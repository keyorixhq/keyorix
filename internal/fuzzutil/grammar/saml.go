package grammar

import "fmt"

// SAMLAssertionNS is the SAML 2.0 assertion namespace URI.
const SAMLAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

// DecodeSAMLFragment turns the fuzzer's bytes into (shape, fragment) for the SAML
// transitive target's Subject-sibling slot. It is the grammar counterpart to that
// target's raw ([]byte fragment, uint8 shape) input: instead of mutating fragment
// bytes (which stall the instant they stop being well-formed XML in context), the
// fuzzer selects a structural SAML shape and the builder emits a well-formed
// fragment realising it. shape is returned in [0,4) to match the existing
// target's shape%4 contract.
//
// The shapes it can emit are exactly the ones the existing target's seeds cover,
// generalised so the engine can combine them:
//   - a correctly-namespaced NameID (benign)
//   - a foreign-namespace NameID look-alike (the GO-2026-6909 namespace-confusion
//     probe)
//   - a prefix-rebound NameID (a saml: prefix rebound to a non-SAML URI, or a
//     foreign prefix rebound to the SAML URI)
//   - deep-nesting / wide-attribute floods (bounded-work probes)
//   - comment / CDATA-split siblings
func DecodeSAMLFragment(data []byte) (fragment string, shape uint8) {
	r := &reader{data: data}
	shape = r.byte() % 4

	switch r.byte() % 7 {
	case 0:
		fragment = ""
	case 1:
		// Correctly-namespaced, unrelated sibling.
		fragment = fmt.Sprintf(`<saml:Attribute xmlns:saml=%q Name=%q><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>`,
			SAMLAssertionNS, "a"+string(r.take(8)), escapeText(string(r.take(8))))
	case 2:
		// Foreign-namespace NameID look-alike — the namespace-confusion probe.
		fragment = fmt.Sprintf(`<evil:NameID xmlns:evil=%q>%s</evil:NameID>`,
			"urn:evil:"+string(r.take(8)), escapeText(string(r.take(16))))
	case 3:
		// A saml: prefix rebound to a non-SAML URI, then a NameID under it.
		fragment = fmt.Sprintf(`<saml:Marker xmlns:saml=%q><saml:NameID>%s</saml:NameID></saml:Marker>`,
			"urn:not-saml:"+string(r.take(6)), escapeText(string(r.take(16))))
	case 4:
		// Bounded-work flood built by the XML grammar (deep chain or wide).
		doc := DecodeXML(r.data[r.pos:])
		fragment = doc.BuildFragment()
	case 5:
		fragment = "<!--" + stripCommentUnsafe(string(r.take(24))) + "-->"
	default:
		var b []byte
		for i, n := 0, r.intn(8); i < n; i++ {
			b = append(b, []byte(fmt.Sprintf(`<saml:X%d xmlns:saml=%q/>`, i, SAMLAssertionNS))...)
		}
		fragment = string(b)
	}
	return fragment, shape
}
