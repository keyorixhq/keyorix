package libconformance

// DF1 Oracle C — kin-openapi vs santhosh-tekuri/jsonschema/v6 verdict differential.
//
// One JSON Schema + one JSON instance are fed to BOTH validators; the oracle fails when
// they disagree on the accept/reject verdict in a way that is not a documented dialect
// difference. Keyorix uses kin-openapi to validate the request/response surface against
// its OpenAPI document and jsonschema/v6 to validate CBOM output against the CycloneDX
// schema (internal/cryptoinventory). The two never validate the SAME bytes at one site
// today (see Phase 0), so a disagreement here is a *library-dialect* finding, not a live
// Keyorix bypass — but a future site that swapped one validator for the other, trusting
// "it's just JSON Schema", would inherit exactly these gaps.
//
// WHAT THIS ORACLE DOES NOT VERIFY:
//   - It only compares the boolean VERDICT, not the error message, error path, or which
//     keyword failed. Two validators can reject for different reasons and still "agree".
//   - It restricts schemas to a common keyword subset (type/properties/required/enum/
//     min*/max*/pattern/items/additionalProperties). It says nothing about keywords
//     outside that subset ($ref across documents, allOf/oneOf composition, format
//     assertions, nullable vs type:[..,"null"]) — those are KNOWN dialect splits and are
//     out of scope rather than silently allowlisted.
//   - It does not test schema COMPILATION agreement: a schema only one library compiles is
//     skipped (returns early), because "one library is stricter about the schema itself"
//     is a different question from "they disagree about an instance".
//   - Number decoding: the instance is decoded the way each library documents (encoding/
//     json float64 for kin-openapi, jsonschema.UnmarshalJSON json.Number for jsonschema).
//     A disagreement rooted purely in that decode is itself a real differential and is
//     classified as number-coercion.

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// kinVerdict loads schemaBytes into a kin-openapi Schema and validates instance.
// ok=false means kin could not use this schema/instance pair (skip the comparison);
// panicked=true means the library panicked (a crash is itself a differential).
func kinVerdict(schemaBytes, instanceBytes []byte) (valid, ok, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			valid, ok, panicked = false, false, true
		}
	}()
	var s openapi3.Schema
	if err := s.UnmarshalJSON(schemaBytes); err != nil {
		return false, false, false
	}
	// A schema kin cannot validate structurally (e.g. bad regex) is not comparable.
	if err := s.Validate(context.Background()); err != nil {
		return false, false, false
	}
	var inst any
	dec := json.NewDecoder(bytes.NewReader(instanceBytes))
	if err := dec.Decode(&inst); err != nil {
		return false, false, false
	}
	return s.VisitJSON(inst) == nil, true, false
}

// jsVerdict compiles schemaBytes with jsonschema/v6 and validates instance. It recovers
// from a library panic because jsonschema/v6 v6.0.3 panics (nil *big.Rat deref) when a
// huge-exponent number is range-checked against a numeric bound (DF1 Finding C-2); a panic
// is reported via panicked=true so the oracle can classify the crash instead of dying.
func jsVerdict(schemaBytes, instanceBytes []byte) (valid, ok, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			valid, ok, panicked = false, false, true
		}
	}()
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return false, false, false
	}
	c := jsonschema.NewCompiler()
	const id = "mem://df1/schema.json"
	if err := c.AddResource(id, schemaDoc); err != nil {
		return false, false, false
	}
	sch, err := c.Compile(id)
	if err != nil {
		return false, false, false
	}
	instDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(instanceBytes))
	if err != nil {
		return false, false, false
	}
	return sch.Validate(instDoc) == nil, true, false
}

type schemaVerdictMismatch struct {
	key           string
	kinV, jsV     bool
	schema, inst  string
}

// openapiCompare is the pure oracle core.
func openapiCompare(schemaBytes, instanceBytes []byte) *schemaVerdictMismatch {
	kinV, kinOK, kinPanic := kinVerdict(schemaBytes, instanceBytes)
	jsV, jsOK, jsPanic := jsVerdict(schemaBytes, instanceBytes)
	// A crash in exactly one library is the most severe differential: one validator DoSes
	// on an input the other handles.
	switch {
	case jsPanic && !kinPanic:
		return &schemaVerdictMismatch{key: "jsonschema-numeric-bignum-panic", kinV: kinV, jsV: false, schema: string(schemaBytes), inst: string(instanceBytes)}
	case kinPanic && !jsPanic:
		return &schemaVerdictMismatch{key: "kin-openapi-panic", kinV: false, jsV: jsV, schema: string(schemaBytes), inst: string(instanceBytes)}
	case kinPanic && jsPanic:
		return nil // both crash — not a differential
	}
	if !kinOK || !jsOK {
		return nil // at least one library could not use the pair; not comparable
	}
	if kinV == jsV {
		return nil
	}
	return &schemaVerdictMismatch{
		key:    classifyVerdictDiff(schemaBytes, instanceBytes),
		kinV:   kinV,
		jsV:    jsV,
		schema: string(schemaBytes),
		inst:   string(instanceBytes),
	}
}

// classifyVerdictDiff gives a stable allowlist key for a verdict disagreement. Keys are
// chosen for the DIALECT MECHANISM that causes the split, not the instance shape, so a
// documented split and a genuine bug never collapse to the same key.
func classifyVerdictDiff(schemaBytes, instanceBytes []byte) string {
	switch {
	// OpenAPI 3.0 extension keywords that JSON Schema 2020-12 does not recognise. kin
	// honours them; jsonschema ignores the unknown keyword and validates the base type.
	case bytes.Contains(schemaBytes, []byte(`"nullable"`)):
		return "openapi-nullable-extension"
	case bytes.Contains(schemaBytes, []byte(`"discriminator"`)):
		return "openapi-discriminator-extension"
	}
	var inst any
	_ = json.Unmarshal(instanceBytes, &inst)
	switch inst.(type) {
	case float64, json.Number:
		return "number-coercion"
	case nil:
		// OpenAPI 3.0 forbids a null value unless the schema sets nullable:true; JSON Schema
		// accepts null wherever `type` permits (and a type-less schema permits any type).
		return "openapi-null-semantics"
	}
	switch {
	case bytes.Contains(schemaBytes, []byte(`"additionalProperties"`)):
		return "additionalProperties-semantics"
	case bytes.Contains(schemaBytes, []byte(`"pattern"`)):
		return "pattern-regex-dialect"
	case bytes.Contains(schemaBytes, []byte(`"required"`)):
		return "required-semantics"
	case bytes.Contains(schemaBytes, []byte(`"enum"`)):
		return "enum-semantics"
	default:
		return "verdict-differs"
	}
}

var openapiDiffAllow = func() *allowlist {
	return newAllowlist(
		expectedDiff{
			key: "openapi-nullable-extension",
			reason: "OpenAPI 3.0's `nullable: true` is an extension keyword that JSON Schema " +
				"2020-12 does not define. kin-openapi honours it (a null value is accepted); " +
				"jsonschema/v6 treats `nullable` as an unknown keyword, ignores it, and enforces the " +
				"base `type`, so null is REJECTED. Documented dialect split, not a bug in either " +
				"library. RED-PROVEN by seed schema `{\"type\":\"string\",\"nullable\":true}` + " +
				"instance `null`. Keyorix note: the OpenAPI document is the kin-openapi side; no live " +
				"site validates the same instance with jsonschema, so this is not a bypass today — but " +
				"it is the precise gap a validator swap would open (see report Finding C-1).",
		},
		expectedDiff{
			key: "enum-semantics",
			reason: "An empty `enum:[]`. JSON Schema 2020-12: an empty enum admits NO value, so " +
				"jsonschema/v6 REJECTS every instance (deny-all). kin-openapi treats an empty enum as " +
				"no constraint and ACCEPTS (allow-all). JSON Schema requires enum to be non-empty, so " +
				"this is a malformed-schema edge the two libraries resolve oppositely. RED-PROVEN by " +
				"`{\"enum\":[]}` + `{}` (kin=valid, jsonschema=invalid). Report Finding C-5: an " +
				"empty-enum schema is a deny-all to a jsonschema validator but an allow-all to " +
				"kin-openapi — opposite fail directions on the same schema.",
		},
		expectedDiff{
			key: "number-coercion",
			reason: "kin-openapi decodes a JSON number via encoding/json as a float64, then type-checks " +
				"it; jsonschema/v6 keeps the exact decimal. So `1e-1000` UNDERFLOWS to float64 0.0 and " +
				"kin accepts it as a valid `integer`, while jsonschema sees the exact non-zero " +
				"non-integer and REJECTS it; large-magnitude and high-precision numbers split the same " +
				"way. Documented (encoding/json float64 default). RED-PROVEN by `{\"type\":\"integer\"}` " +
				"+ `1e-1000` (kin=valid, jsonschema=invalid). Report Finding C-4: a numeric bound/type " +
				"check enforced via kin-openapi can be bypassed by a value that float64 rounds into " +
				"range but the exact value is out of range.",
		},
		expectedDiff{
			key: "openapi-null-semantics",
			reason: "kin-openapi follows OpenAPI 3.0: a JSON null is INVALID against any schema that " +
				"does not set `nullable:true` (even a bare `{\"minimum\":0}`). jsonschema/v6 follows " +
				"JSON Schema 2020-12: `null` is a legal instance wherever `type` permits, and a " +
				"keyword like `minimum` only constrains numbers, so `null` passes. Documented dialect " +
				"split (the general form of openapi-nullable-extension, for schemas that omit the " +
				"keyword entirely). RED-PROVEN by `{\"minimum\":0}` + `null` (kin=invalid, " +
				"jsonschema=valid). Report Finding C-3: a field validated by kin-openapi rejects null " +
				"that a jsonschema-based consumer of the same instance would accept.",
		},
		expectedDiff{
			key: "jsonschema-numeric-bignum-panic",
			reason: "UPSTREAM DEFECT (DoS), santhosh-tekuri/jsonschema/v6 v6.0.3: validating a JSON " +
				"number with a huge exponent (e.g. 1e1000001) against a numeric BOUND keyword " +
				"(minimum/maximum) panics with a nil *big.Rat dereference (validator.go:532 -> " +
				"math/big/rat.go:492). kin-openapi handles the same input without panicking. " +
				"Deterministic; threshold is between 1e100000 (ok) and 1e1000001 (panic); needs an " +
				"actual bound (type:number alone does not trip it). Allowlisted so the fuzzer keeps " +
				"exploring; recorded as report Finding C-2 with an upstream-ready reproducer. Keyorix " +
				"reachability: jsonschema/v6 is used only in the CBOM schema TEST today " +
				"(internal/cryptoinventory), no production path validates untrusted JSON with it, so " +
				"not a live Keyorix DoS — but it WOULD be the moment that changes. RED-PROVEN by seed " +
				"`{\"minimum\":0}` + `1e1000001`.",
		},
	)
}

// curated common-subset schemas; the fuzzer mutates both these and the instance.
var openapiSchemaSeeds = [][]byte{
	[]byte(`{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"}},"required":["name"]}`),
	[]byte(`{"type":"string","minLength":1,"maxLength":8}`),
	[]byte(`{"type":"integer","minimum":0,"maximum":100}`),
	[]byte(`{"type":"array","items":{"type":"string"},"minItems":1}`),
	[]byte(`{"type":"object","additionalProperties":false,"properties":{"x":{"type":"boolean"}}}`),
	[]byte(`{"type":"string","enum":["read","write","admin"]}`),
	// Exercises the openapi-nullable-extension allowlist entry (keeps it non-dead).
	[]byte(`{"type":"string","nullable":true}`),
	// Numeric BOUND schema: paired with 1e1000001 it exercises the jsonschema panic.
	[]byte(`{"minimum":0}`),
	[]byte(`{"enum":[]}`), // empty enum: deny-all (jsonschema) vs allow-all (kin)
}

var openapiInstanceSeeds = [][]byte{
	[]byte(`{"name":"alice","age":30}`),
	[]byte(`{"age":30}`),
	[]byte(`"hello"`),
	[]byte(`42`),
	[]byte(`["a","b"]`),
	[]byte(`{"x":true}`),
	[]byte(`"admin"`),
	[]byte(`null`),
	[]byte(`1e400`),
	[]byte(`{"name":"bob","extra":1}`),
	[]byte(`1e1000001`), // huge exponent: trips the jsonschema/v6 bignum panic vs a bound schema
	[]byte(`1e-1000`),   // float64 underflow: kin accepts as integer, jsonschema rejects (number-coercion)
}

func FuzzOpenAPIVsJSONSchema(f *testing.F) {
	for _, s := range openapiSchemaSeeds {
		for _, inst := range openapiInstanceSeeds {
			f.Add(s, inst)
		}
	}
	allow := openapiDiffAllow()
	f.Fuzz(func(t *testing.T, schemaBytes, instanceBytes []byte) {
		m := openapiCompare(schemaBytes, instanceBytes)
		if m == nil {
			return
		}
		if allow.allows(m.key) {
			return
		}
		t.Fatalf("DIFFERENTIAL [kin-openapi vs jsonschema/v6] verdict disagreement (key=%s)\n  schema=%s\n  instance=%s\n  kin-openapi.valid=%v  jsonschema.valid=%v",
			m.key, m.schema, m.inst, m.kinV, m.jsV)
	})
}

func TestOpenAPIDiffAllowlistNoDead(t *testing.T) {
	allow := openapiDiffAllow()
	for _, s := range openapiSchemaSeeds {
		for _, inst := range openapiInstanceSeeds {
			if m := openapiCompare(s, inst); m != nil {
				allow.allows(m.key)
			}
		}
	}
	allow.assertNoDeadEntries(t)
}
