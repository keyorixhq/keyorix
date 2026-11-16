package libconformance

import "testing"

// TestOpenAPICompare_RedGreen pins both directions of Oracle C.
//
//	GREEN — common-subset schema+instance pairs validate identically under both libraries.
//	RED   — the nullable dialect split is DETECTED and classified precisely, and a key that
//	        is NOT on the allowlist would fail the fuzzer (so the allowlist cannot silently
//	        swallow a genuine disagreement).
func TestOpenAPICompare_RedGreen(t *testing.T) {
	// GREEN: both agree on the overlapping dialect.
	green := []struct{ schema, inst string }{
		{`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`, `{"name":"a"}`},
		{`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`, `{}`},
		{`{"type":"integer","minimum":0,"maximum":100}`, `50`},
		{`{"type":"integer","minimum":0,"maximum":100}`, `250`},
		{`{"type":"string","enum":["read","write"]}`, `"read"`},
		{`{"type":"string","enum":["read","write"]}`, `"admin"`},
	}
	for _, g := range green {
		if m := openapiCompare([]byte(g.schema), []byte(g.inst)); m != nil {
			t.Fatalf("GREEN pair unexpectedly disagreed: schema=%s inst=%s key=%s kin=%v js=%v",
				g.schema, g.inst, m.key, m.kinV, m.jsV)
		}
	}

	// RED (natural dialect split): nullable extension is detected and classified.
	m := openapiCompare([]byte(`{"type":"string","nullable":true}`), []byte(`null`))
	if m == nil {
		t.Fatal("RED: oracle failed to detect the nullable dialect split")
	}
	if m.key != "openapi-nullable-extension" {
		t.Fatalf("RED: nullable split misclassified as %q", m.key)
	}
	if !m.kinV || m.jsV {
		t.Fatalf("RED: expected kin=valid js=invalid, got kin=%v js=%v", m.kinV, m.jsV)
	}

	// A non-allowlisted key must NOT be absorbed: prove the fuzzer would fail on it.
	if openapiDiffAllow().allows("verdict-differs") {
		t.Fatal("RED: generic key verdict-differs must not be on the allowlist")
	}

	// RED (upstream DoS, DF1 Finding C-2): jsonschema/v6 panics on a huge-exponent number
	// range-checked against a bound; kin-openapi does not. The oracle must recover, detect
	// the one-sided crash, and classify it — not die.
	p := openapiCompare([]byte(`{"minimum":0}`), []byte(`1e1000001`))
	if p == nil {
		t.Fatal("RED: jsonschema bignum panic not detected as a differential")
	}
	if p.key != "jsonschema-numeric-bignum-panic" {
		t.Fatalf("RED: panic differential misclassified as %q", p.key)
	}
	// kin-openapi-panic must stay OFF the allowlist (a kin crash would be a new finding).
	if openapiDiffAllow().allows("kin-openapi-panic") {
		t.Fatal("RED: kin-openapi-panic must not be allowlisted")
	}
}
