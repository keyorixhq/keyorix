package libconformance

import (
	"strings"
	"testing"
)

// TestJSONSchemaRefDiff_CycleSafety smoke-tests santhosh-tekuri/jsonschema/v6 v6.0.3 on the
// $ref cycle shapes of KFZ-2026-021. That finding is a google/jsonschema-go defect (a
// non-consuming $ref cycle recursing without bound); google/jsonschema-go is not a
// dependency of this module, so this test does not cover it. It only asks whether santhosh
// compiles and validates the same shapes without panicking, and pins the verdicts it
// returns today.
//
// A stack overflow cannot be recovered: if santhosh ever recursed without bound here, the
// test binary would crash, which `go test` reports as a failure. jsVerdict recovers ordinary
// panics, which fail the test below.
func TestJSONSchemaRefDiff_CycleSafety(t *testing.T) {
	cases := []struct {
		desc, schema, instance string
		wantValid              bool
	}{
		// Self-referential root. santhosh compiles it and rejects every instance (it reports
		// a validation cycle), although 2020-12 would make it equivalent to `true`.
		{"self-ref-root/null", `{"$ref":"#"}`, `null`, false},
		{"self-ref-root/object", `{"$ref":"#"}`, `{}`, false},
		{"self-ref-root/string", `{"$ref":"#"}`, `"hello"`, false},
		// Explicit A->A cycle in $defs: same santhosh behaviour.
		{"defs-cycle/null", `{"$defs":{"A":{"$ref":"#/$defs/A"}},"$ref":"#/$defs/A"}`, `null`, false},
		{"defs-cycle/object", `{"$defs":{"A":{"$ref":"#/$defs/A"}},"$ref":"#/$defs/A"}`, `{}`, false},
		// Legal recursive tree: valid as long as every child is an object.
		{"recursive-tree/empty", `{"type":"object","properties":{"child":{"$ref":"#"}}}`, `{}`, true},
		{"recursive-tree/nested", `{"type":"object","properties":{"child":{"$ref":"#"}}}`, `{"child":{"child":{}}}`, true},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			valid, ok, panicked, nilDeref := jsVerdict([]byte(c.schema), []byte(c.instance))
			if panicked {
				shape := panicShape{nilDeref: nilDeref, schema: []byte(c.schema), inst: []byte(c.instance)}
				t.Fatalf("santhosh PANICKED on a %s schema (key=%s)", c.desc, classifyJSPanic(shape))
			}
			if !ok {
				t.Fatalf("santhosh no longer compiles %s; re-check the cycle handling and update this pin", c.schema)
			}
			if valid != c.wantValid {
				t.Fatalf("santhosh verdict for %s + %s changed: valid=%v, pinned %v", c.schema, c.instance, valid, c.wantValid)
			}
		})
	}
}

// TestJSONSchemaRefDiff_RedGreen pins both directions of Oracle D on $ref-bearing inputs,
// through refDiffCheck (the fuzz body) wherever the real libraries produce the case.
//
// GREEN: pairs where kin resolves the $ref and both libraries evaluate it must be compared
// (kinOK && jsOK) and agree (no mismatch at all, not merely an allowlisted one).
//
// RED: each $ref-borne split fails refDiffCheck under an allowlist that lacks its key and
// passes under refDiffAllow; a planted divergence that the sibling mechanism does not
// explain keeps the non-allowlisted verdict-differs key.
func TestJSONSchemaRefDiff_RedGreen(t *testing.T) {
	green := []struct{ desc, schema, inst string }{
		{"defs-string/reject-number", `{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x"}`, `42`},
		{"defs-string/accept-string", `{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x"}`, `"hello"`},
		{"recursive-tree/accept-nested", `{"type":"object","properties":{"child":{"$ref":"#"}}}`, `{"child":{"child":{}}}`},
		{"recursive-tree/reject-deep-non-object", `{"type":"object","properties":{"child":{"$ref":"#"}}}`, `{"child":{"child":1}}`},
		{"recursive-array/reject-deep-number", `{"type":"array","items":{"$ref":"#"}}`, `[[],[[1]]]`},
	}
	for _, c := range green {
		t.Run("GREEN/"+c.desc, func(t *testing.T) {
			_, kinOK, _ := kinRefVerdict([]byte(c.schema), []byte(c.inst))
			_, jsOK, _, _ := jsVerdict([]byte(c.schema), []byte(c.inst))
			if !kinOK || !jsOK {
				t.Fatalf("pair not compared (kinOK=%v jsOK=%v): the GREEN case would pass vacuously", kinOK, jsOK)
			}
			if m := refCompare([]byte(c.schema), []byte(c.inst)); m != nil {
				t.Fatalf("unexpected disagreement key=%s kin=%v js=%v", m.key, m.kinV, m.jsV)
			}
			if err := refDiffCheck(newAllowlist(), []byte(c.schema), []byte(c.inst)); err != nil {
				t.Fatalf("refDiffCheck with an empty allowlist: %v", err)
			}
		})
	}

	red := []struct{ desc, schema, inst, key string }{
		{"ref-sibling-ignored", `{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x","minLength":3}`, `"a"`, "openapi-ref-sibling-ignored"},
		{"nullable-through-ref", `{"$defs":{"x":{"type":"string","nullable":true}},"$ref":"#/$defs/x"}`, `null`, "openapi-nullable-extension"},
		{"null-semantics-through-ref", `{"$defs":{"x":{"minimum":0}},"$ref":"#/$defs/x"}`, `null`, "openapi-null-semantics"},
		{"bignum-panic-through-ref", `{"$defs":{"x":{"minimum":0}},"$ref":"#/$defs/x"}`, `1e1000001`, "jsonschema-numeric-bignum-panic"},
	}
	for _, c := range red {
		t.Run("RED/"+c.desc, func(t *testing.T) {
			// Every key except the one under test.
			var rows []expectedDiff
			for _, k := range []string{"openapi-ref-sibling-ignored", "openapi-nullable-extension", "enum-semantics",
				"number-coercion", "openapi-null-semantics", "jsonschema-numeric-bignum-panic"} {
				if k != c.key {
					rows = append(rows, expectedDiff{key: k, reason: "red-proof narrow allowlist"})
				}
			}
			err := refDiffCheck(newAllowlist(rows...), []byte(c.schema), []byte(c.inst))
			if err == nil || !strings.Contains(err.Error(), "key="+c.key+")") {
				t.Fatalf("RED: refDiffCheck without %q must fail with that key, got %v", c.key, err)
			}
			if err := refDiffCheck(refDiffAllow(), []byte(c.schema), []byte(c.inst)); err != nil {
				t.Fatalf("GREEN: refDiffAllow must document the split: %v", err)
			}
		})
	}

	t.Run("RED/planted-split-not-explained-by-siblings", func(t *testing.T) {
		// A kin side that accepts everything. santhosh rejects 42 against a string schema
		// both with and without the minLength sibling, so stripping does not explain the
		// split and it must NOT be keyed openapi-ref-sibling-ignored.
		acceptAll := func(_, _ []byte) (bool, bool, bool) { return true, true, false }
		schema := []byte(`{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x","minLength":3}`)
		m := refCompareWith(acceptAll, schema, []byte(`42`))
		if m == nil {
			t.Fatal("planted divergence not detected")
		}
		if m.key != "verdict-differs" || refDiffAllow().allows(m.key) {
			t.Fatalf("planted divergence keyed %q (allowlisted=%v); want the non-allowlisted verdict-differs",
				m.key, refDiffAllow().allows(m.key))
		}
	})
}
