package libconformance

import "testing"

// TestXMLCompare_RedGreen is the committed red/green proof for the Oracle-A core
// (xmlCompare / walkCompare). It pins both directions so the oracle is not "a guard
// nobody has watched fail":
//
//   GREEN — inputs both libraries read identically yield no mismatch.
//   RED   — a genuine divergence is DETECTED and classified, including a DECLARED-
//           namespace disagreement built by hand (the dangerous class the allowlist must
//           NOT swallow), proving the oracle fires on exactly the shape it exists for.
//
// The natural undeclared-prefix divergence (`<x:a/>`) is red-proven here too; it is the
// documented, allowlisted class, so the FUZZ target tolerates it while this test confirms
// the detection path still sees it.
func TestXMLCompare_RedGreen(t *testing.T) {
	// GREEN: structurally identical readings.
	for _, good := range []string{
		`<a><b x="1">t</b><c/></a>`,
		`<Response><Assertion ID="_1"><Subject><NameID>alice</NameID></Subject></Assertion></Response>`,
		`<a xmlns="urn:d"><b>1</b></a>`,
		`<r xmlns:z="urn:z"><z:e a="1">x</z:e></r>`,
	} {
		if m := xmlCompare([]byte(good)); m != nil {
			t.Fatalf("GREEN input %q unexpectedly flagged: key=%s %s", good, m.key, m.detail)
		}
	}

	// RED (natural): undeclared prefix is detected and correctly classified.
	if m := xmlCompare([]byte(`<x:a/>`)); m == nil {
		t.Fatal("RED: oracle failed to detect the undeclared-prefix divergence `<x:a/>`")
	} else if m.key != "undeclared-prefix-ns" {
		t.Fatalf("RED: undeclared-prefix misclassified as %q (%s)", m.key, m.detail)
	}

	// RED (synthetic, dangerous class): a DECLARED-namespace disagreement must fire and
	// must NOT be absorbed by the undeclared-prefix allowlist entry. This is the
	// signature-wrapping-relevant case: two readings bind the same local name to two
	// different, both-declared namespaces.
	declared := map[string]bool{"": true, "urn:good": true, "urn:evil": true}
	aTree := &xmlNode{name: nsName("urn:good", "Assertion"), attrs: map[string]string{}}
	bTree := &xmlNode{name: nsName("urn:evil", "Assertion"), attrs: map[string]string{}}
	m := walkCompare(aTree, bTree, declared)
	if m == nil {
		t.Fatal("RED: oracle failed to detect a DECLARED-namespace disagreement")
	}
	if m.key != "declared-namespace-uri-differs" {
		t.Fatalf("RED: declared-namespace disagreement misclassified as %q", m.key)
	}
	if xmlDiffAllow().allows(m.key) {
		t.Fatalf("RED: dangerous key %q must NOT be on the allowlist", m.key)
	}

	// RED: a smuggled-text divergence fires.
	tA := &xmlNode{name: "|NameID", attrs: map[string]string{}, text: "alice"}
	tB := &xmlNode{name: "|NameID", attrs: map[string]string{}, text: "admin"}
	if m := walkCompare(tA, tB, declared); m == nil || m.key != "text-differs" {
		t.Fatalf("RED: text divergence not detected/classified (got %v)", m)
	}
}
