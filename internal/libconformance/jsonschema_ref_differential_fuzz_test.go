package libconformance

// DF1 Oracle D — $ref/$defs/$dynamicRef territory differential:
// getkin/kin-openapi vs santhosh-tekuri/jsonschema/v6.
//
// FuzzOpenAPIVsJSONSchema (Oracle C) deliberately restricts schemas to the
// non-$ref common subset, noting that the two libraries' $ref-resolution models
// differ enough to drown in noise. This oracle covers that excluded territory.
//
// KFZ-2026-021 context: google/jsonschema-go v0.4.3 (a non-consuming $ref cycle
// caused unbounded recursion) is NOT vendored in this module — see JF4 report
// (.scratch/REPORT.md, Inventory section).  That library's bug shape is "cycle
// not consumed → infinite recursion → stack overflow".  Stack overflow is a
// non-recoverable runtime.Error; the Go fuzzer detects it as a binary crash, not
// a classified differential.  This oracle exercises the same cycle-shaped seeds
// against santhosh and kin-openapi: if santhosh has an analogous bug, the fuzzer
// reports a crash.
//
// KFZ-2026-086 (santhosh nil *big.Rat deref on huge-exponent numeric bound) is
// already on the allowlist here (seed: {"minimum":0} + 1e1000001) for the same
// reason it appears in FuzzOpenAPIVsJSONSchema: fuzz mutations of any seed can
// produce a numeric bound + huge exponent, so the allowlist entry must exist.
//
// WHAT THIS ORACLE DOES NOT VERIFY:
//   - Schemas where only one library compiles the input (kinOK=false or jsOK=false
//     at the kin-openapi Validate step) — those are skipped, not classified.
//   - $ref to external URIs (denyLoader refuses them from santhosh).
//   - $schema dialect assertions.
//   - unevaluatedProperties / unevaluatedItems.
//   - Verdict-divergence reasons (error path, keyword that failed); only
//     accept/reject is compared.

import (
	"testing"
)

// refSchemaSeeds are schemas that contain $ref, $defs, or $dynamicRef territory.
// They are intentionally split into two groups:
//
//  1. "cycle seeds" — schemas with a $ref cycle; they verify santhosh's cycle
//     detection does not loop or overflow (the KFZ-2026-021 shape).  Both
//     libraries must process these without crashing.
//
//  2. "dialect seeds" — schemas that mix common-subset keywords with $ref-family
//     keywords; they may produce verdict splits already covered by Oracle C's
//     allowlist (openapi-nullable-extension, etc.) and reveal new $ref-specific
//     splits.
var refSchemaSeeds = [][]byte{
	// --- cycle seeds (KFZ-2026-021 shape) ---
	// Self-referential: {"$ref":"#"} is equivalent to `true` in JSON Schema
	// 2020-12 (no constraints, cycle resolves to unconstrained); santhosh and
	// kin-openapi may treat it differently or fail to compile it.
	[]byte(`{"$ref":"#"}`),
	// Explicitly cyclic via $defs: A refers to itself.
	[]byte(`{"$defs":{"A":{"$ref":"#/$defs/A"}},"$ref":"#/$defs/A"}`),
	// Recursive tree: an object whose "child" property is another instance of
	// the same schema.  Legal recursive schema; validates {} as valid (no
	// required child).
	[]byte(`{"type":"object","properties":{"child":{"$ref":"#"}}}`),

	// --- $defs dialect seeds ---
	// $defs is JSON Schema 2020-12 vocabulary; kin-openapi (OpenAPI 3.0) does
	// not define it.  If kin-openapi's Validate() fails on the unresolved $ref,
	// kinOK=false and the pair is skipped (not a verdict differential).
	[]byte(`{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x"}`),
	[]byte(`{"type":"object","properties":{"name":{"$ref":"#/$defs/name"}},"$defs":{"name":{"type":"string","minLength":1}}}`),

	// --- $dynamicRef / $dynamicAnchor seeds ---
	// JSON Schema 2020-12 feature; kin-openapi does not support it.
	[]byte(`{"$dynamicAnchor":"item","type":"string"}`),
	[]byte(`{"$defs":{"base":{"$dynamicAnchor":"item","type":"string"}},"$dynamicRef":"#item"}`),

	// --- inherited from Oracle C: seeds that exercise the full allowlist ---
	// Keep these so assertNoDeadEntries passes after fuzz mutations.
	[]byte(`{"type":"string","nullable":true}`), // openapi-nullable-extension
	[]byte(`{"enum":[]}`),                       // enum-semantics
	[]byte(`{"type":"integer"}`),                // number-coercion (1e-1000 instance)
	[]byte(`{"minimum":0}`),                     // openapi-null-semantics + bignum-panic
	[]byte(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`),
}

var refInstanceSeeds = [][]byte{
	[]byte(`{}`),
	[]byte(`{"name":"alice"}`),
	[]byte(`{"child":{}}`),
	[]byte(`"hello"`),
	[]byte(`42`),
	[]byte(`null`),
	[]byte(`1e1000001`), // KFZ-2026-086 shape: huge exponent
	[]byte(`1e-1000`),   // number-coercion: underflows to float64 0.0
}

// refDiffAllow holds tolerated verdict-divergence classes for Oracle D.
// All Oracle-C entries are inherited here because fuzz mutations of any seed can
// reach the same schema territory; a mutation of {"$ref":"#"} can easily produce
// {"$ref":"#","nullable":true} or {"$ref":"#","minimum":0} + a huge instance.
// New $ref-specific entries are added below as they are found and classified.
var refDiffAllow = func() *allowlist {
	return newAllowlist(
		expectedDiff{
			key: "openapi-nullable-extension",
			reason: "Inherited from Oracle C: OpenAPI 3.0 `nullable:true` is accepted by " +
				"kin-openapi; jsonschema/v6 ignores it and enforces the base `type`. See " +
				"openapiDiffAllow for the full reasoning. RED-PROVEN by " +
				"`{\"type\":\"string\",\"nullable\":true}` + `null`.",
		},
		expectedDiff{
			key: "enum-semantics",
			reason: "Inherited from Oracle C: empty `enum:[]`. JSON Schema 2020-12 denies " +
				"everything (no value is a member of an empty enum); kin-openapi treats it as " +
				"no constraint (allow-all). RED-PROVEN by `{\"enum\":[]}` + `{}`.",
		},
		expectedDiff{
			key: "number-coercion",
			reason: "Inherited from Oracle C: kin-openapi decodes numbers as float64; " +
				"santhosh keeps exact decimal. `1e-1000` underflows to 0.0 for float64 " +
				"and kin accepts it as a valid integer. RED-PROVEN by `{\"type\":\"integer\"}` " +
				"+ `1e-1000`.",
		},
		expectedDiff{
			key: "openapi-null-semantics",
			reason: "Inherited from Oracle C: kin-openapi rejects null for any schema without " +
				"`nullable:true`; jsonschema/v6 accepts null where `type` does not constrain it. " +
				"RED-PROVEN by `{\"minimum\":0}` + `null`.",
		},
		expectedDiff{
			key: "jsonschema-numeric-bignum-panic",
			reason: "Inherited from Oracle C: santhosh-tekuri/jsonschema/v6 v6.0.3 panics (nil " +
				"*big.Rat deref, validator.go:532) when validating a huge-exponent number against " +
				"a numeric bound keyword.  Deterministic at exponent > 1e6 with an actual bound. " +
				"kin-openapi handles the same input without panicking.  RED-PROVEN by " +
				"`{\"minimum\":0}` + `1e1000001`.",
		},
	)
}

// FuzzJSONSchemaRefDifferential is a differential fuzz target over the $ref/
// $defs/$dynamicRef territory that FuzzOpenAPIVsJSONSchema deliberately excludes.
//
// It reuses the same two validators (kin-openapi and santhosh) and the same
// openapiCompare oracle function; the difference is the seed corpus, which
// focuses on:
//
//   - $ref cycles (KFZ-2026-021 shape — santhosh must not crash)
//   - $defs/$dynamicRef usage (JSON Schema 2020-12 vocabulary, kin-openapi ignores)
//   - Mutations of the above that reach the full OpenAPI 3.0 dialect space
func FuzzJSONSchemaRefDifferential(f *testing.F) {
	for _, s := range refSchemaSeeds {
		for _, inst := range refInstanceSeeds {
			f.Add(s, inst)
		}
	}

	allow := refDiffAllow()
	f.Fuzz(func(t *testing.T, schemaBytes, instanceBytes []byte) {
		if len(schemaBytes) > 1<<14 || len(instanceBytes) > 1<<14 {
			return
		}
		m := openapiCompare(schemaBytes, instanceBytes)
		if m == nil {
			return
		}
		if allow.allows(m.key) {
			return
		}
		t.Fatalf("DIFFERENTIAL [kin-openapi vs jsonschema/v6, $ref-territory] "+
			"verdict disagreement (key=%s)\n  schema=%s\n  instance=%s\n  "+
			"kin-openapi.valid=%v  jsonschema.valid=%v",
			m.key, m.schema, m.inst, m.kinV, m.jsV)
	})
}

// TestRefDiffAllowlistNoDead verifies no allowlist entry is dead over the seed
// corpus.  A dead entry is a "this divergence is documented" claim that no seed
// actually exercises — exactly the stale-skip shape.
func TestRefDiffAllowlistNoDead(t *testing.T) {
	allow := refDiffAllow()
	for _, s := range refSchemaSeeds {
		for _, inst := range refInstanceSeeds {
			if m := openapiCompare(s, inst); m != nil {
				allow.allows(m.key)
			}
		}
	}
	allow.assertNoDeadEntries(t)
}
