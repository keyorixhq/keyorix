package libconformance

import "testing"

// TestOpenAPIClassifier_KeysTiedToMechanism is the red/green proof that every allowlisted
// verdict key is chosen only when the mechanism it names actually caused the split. Before
// the fix the key came from the instance's top-level JSON type or a schema substring, so
// an empty-enum split on `42` was filed as number-coercion and any jsonschema panic was
// filed as the bignum panic.
func TestOpenAPIClassifier_KeysTiedToMechanism(t *testing.T) {
	allow := openapiDiffAllow()

	// GREEN: an empty enum with a plain integer is an enum-semantics split, not a number one.
	if m := openapiCompare([]byte(`{"enum":[]}`), []byte(`42`)); m == nil || m.key != "enum-semantics" {
		t.Fatalf("`{\"enum\":[]}` + 42 must be enum-semantics, got %+v", m)
	}

	// RED: a verdict split on a numeric instance that float64 represents exactly is NOT
	// number-coercion, so it must not be allowlisted (kin=invalid, js=valid, hand-built).
	for _, key := range []string{
		classifyVerdictDiff([]byte(`{"minimum":0}`), []byte(`5`), false, true),
		classifyVerdictDiff([]byte(`{"minimum":0}`), []byte(`5`), true, false),
	} {
		if allow.allows(key) {
			t.Fatalf("numeric split with exact float64 filed under allowlisted key %q", key)
		}
	}

	// GREEN: a genuine float64 rounding split keeps number-coercion.
	if k := classifyVerdictDiff([]byte(`{"type":"integer"}`), []byte(`1e-1000`), true, false); k != "number-coercion" {
		t.Fatalf("1e-1000 underflow must be number-coercion, got %q", k)
	}

	// Null keys need a null in the instance AND the matching direction.
	if k := classifyVerdictDiff([]byte(`{"type":"string","nullable":true}`), []byte(`"x"`), true, false); allow.allows(k) {
		t.Fatalf("nullable schema with a non-null instance filed under %q", k)
	}
	if k := classifyVerdictDiff([]byte(`{"type":"string","nullable":true}`), []byte(`null`), false, true); allow.allows(k) {
		t.Fatalf("nullable split in the wrong direction filed under %q", k)
	}
	if k := classifyVerdictDiff([]byte(`{"minimum":0}`), []byte(`null`), true, false); allow.allows(k) {
		t.Fatalf("null-semantics split in the wrong direction filed under %q", k)
	}
	if k := classifyVerdictDiff([]byte(`{"minimum":0}`), []byte(`null`), false, true); k != "openapi-null-semantics" {
		t.Fatalf("`{\"minimum\":0}` + null (kin=invalid js=valid) must be openapi-null-semantics, got %q", k)
	}

	// An enum word in a string value is not an empty enum.
	if k := classifyVerdictDiff([]byte(`{"const":"enum","x":{"enum":[1]}}`), []byte(`"a"`), true, false); allow.allows(k) {
		t.Fatalf("non-empty enum filed under allowlisted key %q", k)
	}
}

// TestOpenAPIPanicKeyTiedToBignum: only the documented nil *big.Rat panic (numeric bound +
// huge exponent) takes the allowlisted key; any other jsonschema panic is jsonschema-panic.
func TestOpenAPIPanicKeyTiedToBignum(t *testing.T) {
	allow := openapiDiffAllow()

	if m := openapiCompare([]byte(`{"minimum":0}`), []byte(`1e1000001`)); m == nil || m.key != "jsonschema-numeric-bignum-panic" {
		t.Fatalf("documented bignum panic must keep its key, got %+v", m)
	}

	good := panicShape{nilDeref: true, schema: []byte(`{"minimum":0}`), inst: []byte(`1e1000001`)}
	if k := classifyJSPanic(good); k != "jsonschema-numeric-bignum-panic" {
		t.Fatalf("bignum panic shape misclassified as %q", k)
	}
	for name, p := range map[string]panicShape{
		"not-a-nil-deref":  {nilDeref: false, schema: good.schema, inst: good.inst},
		"no-numeric-bound": {nilDeref: true, schema: []byte(`{"type":"number"}`), inst: good.inst},
		"small-exponent":   {nilDeref: true, schema: good.schema, inst: []byte(`1e100`)},
		"bound-in-string":  {nilDeref: true, schema: []byte(`{"const":"minimum"}`), inst: good.inst},
	} {
		k := classifyJSPanic(p)
		if k != "jsonschema-panic" || allow.allows(k) {
			t.Fatalf("%s: panic filed under %q (allowlisted=%v)", name, k, allow.allows(k))
		}
	}
}
