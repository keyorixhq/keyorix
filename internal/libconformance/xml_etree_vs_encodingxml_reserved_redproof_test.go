package libconformance

import "testing"

// TestXMLCompare_ReservedPrefixNotAllowlisted is the red/green proof for the
// undeclared-prefix-ns classifier. That key may only be chosen when the prefix really has
// no in-scope xmlns:<prefix> binding. A rebinding of the reserved `xml` prefix (or a
// `xmlns:` element prefix) is a DECLARED-namespace split on the SAML Assertion shape and
// must come back under a key that is not allowlisted.
func TestXMLCompare_ReservedPrefixNotAllowlisted(t *testing.T) {
	allow := xmlDiffAllow()

	// RED: the review's probe document. Both libraries accept it; etree resolves the
	// declared URN, encoding/xml resolves the implicit W3C namespace of `xml:`.
	probe := `<Response xmlns:xml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<xml:Assertion ID="_a"><xml:NameID>admin</xml:NameID></xml:Assertion></Response>`
	m := xmlCompare([]byte(probe))
	if m == nil {
		t.Fatal("RED: oracle failed to detect the xml: prefix rebinding split")
	}
	if m.key == "undeclared-prefix-ns" || allow.allows(m.key) {
		t.Fatalf("RED: xml: rebinding filed under allowlisted key %q (%s)", m.key, m.detail)
	}

	// RED: an element whose prefix is `xmlns` is reserved too.
	if m := xmlCompare([]byte(`<r><xmlns:b/></r>`)); m != nil {
		if m.key == "undeclared-prefix-ns" || allow.allows(m.key) {
			t.Fatalf("RED: xmlns: element prefix filed under allowlisted key %q", m.key)
		}
	}

	// RED: a prefix that IS declared in scope (on an ancestor) but differs between the
	// libraries is not "undeclared", whatever the document-wide URI set says.
	if m := xmlCompare([]byte(`<r xmlns:q="urn:q"><q:a/></r>`)); m != nil {
		t.Fatalf("GREEN input flagged: key=%s %s", m.key, m.detail)
	}

	// GREEN: a genuinely undeclared prefix still yields the allowlisted key, also when a
	// DIFFERENT prefix is declared elsewhere in the document.
	for _, doc := range []string{`<x:a/>`, `<r xmlns:z="urn:z"><x:a/></r>`} {
		m := xmlCompare([]byte(doc))
		if m == nil || m.key != "undeclared-prefix-ns" {
			t.Fatalf("GREEN: %q must yield undeclared-prefix-ns, got %v", doc, m)
		}
		if !allow.allows(m.key) {
			t.Fatalf("GREEN: undeclared-prefix-ns must stay allowlisted for %q", doc)
		}
	}
}
