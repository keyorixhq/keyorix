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
	"errors"
	"math/big"
	"runtime"
	"strconv"
	"strings"
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

// denyLoader refuses every external schema load: fuzz-chosen schemas must never make the
// harness read files or fetch URLs ($ref to file:// or http://).
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, errors.New("external load denied: " + url)
}

// jsVerdict compiles schemaBytes with jsonschema/v6 and validates instance. It recovers
// from a library panic because jsonschema/v6 v6.0.3 panics (nil *big.Rat deref) when a
// huge-exponent number is range-checked against a numeric bound (DF1 Finding C-2); a panic
// is reported via panicked=true (nilDeref says whether it was a nil-pointer runtime error)
// so the oracle can classify the crash instead of dying.
func jsVerdict(schemaBytes, instanceBytes []byte) (valid, ok, panicked, nilDeref bool) {
	defer func() {
		if r := recover(); r != nil {
			valid, ok, panicked = false, false, true
			if re, isRT := r.(runtime.Error); isRT {
				nilDeref = strings.Contains(re.Error(), "nil pointer dereference")
			}
		}
	}()
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return false, false, false, false
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	const id = "mem://df1/schema.json"
	if err := c.AddResource(id, schemaDoc); err != nil {
		return false, false, false, false
	}
	sch, err := c.Compile(id)
	if err != nil {
		return false, false, false, false
	}
	instDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(instanceBytes))
	if err != nil {
		return false, false, false, false
	}
	return sch.Validate(instDoc) == nil, true, false, false
}

type schemaVerdictMismatch struct {
	key          string
	kinV, jsV    bool
	schema, inst string
}

// openapiCompare is the pure oracle core.
func openapiCompare(schemaBytes, instanceBytes []byte) *schemaVerdictMismatch {
	return compareVerdicts(kinVerdict, schemaBytes, instanceBytes)
}

// compareVerdicts runs kinFn (the kin-openapi side) and jsVerdict on one pair and
// classifies any disagreement. Oracle C passes kinVerdict; Oracle D passes kinRefVerdict.
func compareVerdicts(kinFn func(schemaBytes, instanceBytes []byte) (valid, ok, panicked bool), schemaBytes, instanceBytes []byte) *schemaVerdictMismatch {
	kinV, kinOK, kinPanic := kinFn(schemaBytes, instanceBytes)
	jsV, jsOK, jsPanic, jsNilDeref := jsVerdict(schemaBytes, instanceBytes)
	// A crash in exactly one library is the most severe differential: one validator DoSes
	// on an input the other handles.
	switch {
	case jsPanic && !kinPanic:
		key := classifyJSPanic(panicShape{nilDeref: jsNilDeref, schema: schemaBytes, inst: instanceBytes})
		return &schemaVerdictMismatch{key: key, kinV: kinV, jsV: false, schema: string(schemaBytes), inst: string(instanceBytes)}
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
		key:    classifyVerdictDiff(schemaBytes, instanceBytes, kinV, jsV),
		kinV:   kinV,
		jsV:    jsV,
		schema: string(schemaBytes),
		inst:   string(instanceBytes),
	}
}

// decodeJSONNumbers decodes b keeping numbers as json.Number (no float64 rounding).
func decodeJSONNumbers(b []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

// anyNode reports whether pred holds for v or any value nested in it.
func anyNode(v any, pred func(any) bool) bool {
	if pred(v) {
		return true
	}
	switch t := v.(type) {
	case map[string]any:
		for _, c := range t {
			if anyNode(c, pred) {
				return true
			}
		}
	case []any:
		for _, c := range t {
			if anyNode(c, pred) {
				return true
			}
		}
	}
	return false
}

// schemaHasKey reports whether any object in the decoded schema has key with a value
// accepted by valOK (nil accepts any). It walks structure, so a keyword name that only
// appears inside a string value does not count.
func schemaHasKey(schemaBytes []byte, key string, valOK func(any) bool) bool {
	doc, ok := decodeJSONNumbers(schemaBytes)
	if !ok {
		return false
	}
	return anyNode(doc, func(n any) bool {
		m, isMap := n.(map[string]any)
		if !isMap {
			return false
		}
		v, has := m[key]
		return has && (valOK == nil || valOK(v))
	})
}

func isEmptyArray(v any) bool { a, ok := v.([]any); return ok && len(a) == 0 }

// instanceHasNull reports whether the instance contains a JSON null anywhere.
func instanceHasNull(instanceBytes []byte) bool {
	doc, ok := decodeJSONNumbers(instanceBytes)
	return ok && anyNode(doc, func(n any) bool { return n == nil })
}

// numberCoerces reports whether float64 decoding changes the value of the JSON number
// token (underflow, rounding, or out of float64 range) — the one mechanism number-coercion
// names.
func numberCoerces(tok string) bool {
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		return true // out of float64 range: encoding/json would reject it, jsonschema keeps it
	}
	exact, ok := new(big.Rat).SetString(tok)
	if !ok {
		return true // too large for exact comparison, so certainly not float64-representable
	}
	fr := new(big.Rat).SetFloat64(f)
	return fr == nil || fr.Cmp(exact) != 0
}

// instanceCoerces reports whether any number in the instance is changed by float64 decoding.
func instanceCoerces(instanceBytes []byte) bool {
	doc, ok := decodeJSONNumbers(instanceBytes)
	return ok && anyNode(doc, func(n any) bool {
		num, isNum := n.(json.Number)
		return isNum && numberCoerces(num.String())
	})
}

// hugeExponent reports whether tok is a JSON number whose decimal exponent exceeds 1e6.
func hugeExponent(tok string) bool {
	i := strings.IndexAny(tok, "eE")
	if i < 0 {
		return false
	}
	e, err := strconv.ParseInt(strings.TrimPrefix(tok[i+1:], "+"), 10, 64)
	if err != nil {
		return errors.Is(err, strconv.ErrRange) // exponent beyond int64 is huge by definition
	}
	return e > 1_000_000 || e < -1_000_000
}

// panicShape is what classifyJSPanic needs to decide whether a jsonschema panic is the
// documented bignum one.
type panicShape struct {
	nilDeref     bool
	schema, inst []byte
}

// classifyJSPanic gives the documented key only for the shape of DF1 Finding C-2: a nil
// pointer runtime error, a schema with a numeric bound keyword, and an instance number with
// an exponent above 1e6. Any other jsonschema panic is a new finding under a key that is not
// allowlisted.
func classifyJSPanic(p panicShape) string {
	hasBound := false
	for _, kw := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"} {
		if schemaHasKey(p.schema, kw, nil) {
			hasBound = true
			break
		}
	}
	doc, ok := decodeJSONNumbers(p.inst)
	huge := ok && anyNode(doc, func(n any) bool {
		num, isNum := n.(json.Number)
		return isNum && hugeExponent(num.String())
	})
	if p.nilDeref && hasBound && huge {
		return "jsonschema-numeric-bignum-panic"
	}
	return "jsonschema-panic"
}

// classifyVerdictDiff gives a stable allowlist key for a verdict disagreement. A key is
// chosen only when the mechanism it names is present in the pair AND the verdict direction
// matches the documented one, so a documented split and a genuine bug never share a key.
// Anything that fits no documented mechanism is "verdict-differs" (not allowlisted).
func classifyVerdictDiff(schemaBytes, instanceBytes []byte, kinV, jsV bool) string {
	hasNull := instanceHasNull(instanceBytes)
	switch {
	// OpenAPI 3.0 extension keywords that JSON Schema 2020-12 does not recognise. kin
	// honours nullable (null accepted); jsonschema ignores it and enforces the base type.
	case hasNull && kinV && !jsV && schemaHasKey(schemaBytes, "nullable", nil):
		return "openapi-nullable-extension"
	case schemaHasKey(schemaBytes, "discriminator", nil):
		return "openapi-discriminator-extension"
	// kin allows everything for an empty enum, jsonschema denies everything.
	case kinV && !jsV && schemaHasKey(schemaBytes, "enum", isEmptyArray):
		return "enum-semantics"
	case instanceCoerces(instanceBytes):
		return "number-coercion"
	// OpenAPI 3.0 forbids a null unless nullable:true; JSON Schema accepts null wherever
	// the keywords only constrain other types.
	case hasNull && !kinV && jsV && !schemaHasKey(schemaBytes, "nullable", nil):
		return "openapi-null-semantics"
	case bytes.Contains(schemaBytes, []byte(`"additionalProperties"`)):
		return "additionalProperties-semantics"
	case bytes.Contains(schemaBytes, []byte(`"pattern"`)):
		return "pattern-regex-dialect"
	case bytes.Contains(schemaBytes, []byte(`"required"`)):
		return "required-semantics"
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
