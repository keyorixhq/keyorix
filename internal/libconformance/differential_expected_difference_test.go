package libconformance

// EXPECTED-DIFFERENCE tables for the sibling-implementation differential fuzz
// targets in this package. This file IS the talk slide "where equivalent
// libraries disagree": every entry is a place two libraries Keyorix treats as
// interchangeable do not, in fact, behave identically, with the reasoning for
// why the divergence is accepted rather than a bug to chase.
//
// The contract (per the DP1 task): a differential oracle fails on any
// disagreement class NOT listed here. A listed class is tolerated. Adding a
// class is a deliberate, reviewed act — it records "we looked at this split,
// classified it, and decided it is a benign library-version/dialect difference,
// not a Keyorix defect." An empty (or near-empty) table is the strong default:
// the whole point is that siblings should agree, so every tolerated divergence
// must be justified in the comment next to it.

// yamlExpectedDiff lists tolerated divergence classes between
// go.yaml.in/yaml/v3 v3.0.5 and gopkg.in/yaml.v3 v3.0.1 (see
// FuzzYAMLSiblingDifferential / classifyYAMLSplit for the class vocabulary).
//
// Populated from triage during the DP1 fuzz run. Each key is a classifyYAMLSplit
// output string; the comment on the line is the justification.
var yamlExpectedDiff = map[string]bool{
	// (populated during triage — see .scratch/dp1-REPORT.md findings table)
}

// jsonSchemaExpectedDiff lists tolerated verdict-divergence classes between
// santhosh-tekuri/jsonschema/v6 and getkin/kin-openapi openapi3 schema
// validation (see FuzzJSONSchemaValidatorDifferential). The two implement
// DIFFERENT dialects (JSON Schema draft vs OpenAPI 3.0 Schema Object), so a
// broad set of divergences is expected and listed here by feature.
var jsonSchemaExpectedDiff = map[string]bool{
	// The two validators decode the INSTANCE with different JSON parsers, so some
	// instances parse for one and not the other — a parser differential, not a
	// schema-validation one.

	// santhosh's jsonschema.UnmarshalJSON keeps numbers as json.Number (unbounded);
	// kin decodes via encoding/json into float64 and rejects a number too large for
	// float64. Found by the fuzzer at {"":1e700}. Benign: Keyorix feeds each
	// validator its own idiomatic decode.
	"parse-split:kin-float64-number-range": true,

	// santhosh's UnmarshalJSON REJECTS duplicate object keys; encoding/json (kin's
	// path) keeps last-wins. A real, security-flavoured divergence in the two JSON
	// parsers — recorded here, and also the kind of thing a duplicate-key pre-scan
	// (see FuzzYAMLSiblingDifferential) exists to normalise.
	"parse-split:santhosh-duplicate-key": true,
}

// jsonDecodeExpectedDiff lists tolerated accept/reject divergence classes among
// the three JSON decode paths in FuzzJSONStrictDecodeDifferential.
var jsonDecodeExpectedDiff = map[string]bool{
	// json.Decoder.Decode reads exactly ONE top-level JSON value and leaves any
	// trailing bytes unconsumed; json.Unmarshal rejects trailing non-whitespace
	// ("invalid character after top-level value"). Every Keyorix handler uses
	// Decode without a trailing-byte check, so `{...}{...}`, `{...}garbage` and
	// NDJSON bodies are accepted with only the FIRST value decoded. Documented Go
	// behaviour, not a library bug — but a real HARDENING observation about the
	// handlers (see report: talk material / request-smuggling surface).
	"A-vs-B:trailing-data": true,

	// DisallowUnknownFields (path C) rejects a body carrying a field absent from
	// the struct; the plain Decode path (A, what the handlers use) silently drops
	// it. By design in Keyorix (unknown fields ignored); recorded so the choice is
	// visible rather than invisible.
	"A-vs-C:unknown-field": true,

	// A struct decode SKIPS an unknown field's value and stores a json.RawMessage
	// field as raw bytes, so it never converts the number to a Go float64; a
	// schemaless decode (M) materializes every number into float64 and rejects one
	// that overflows (e.g. {"":1e700}). A genuine, benign value-materialization
	// differential, found by the fuzzer at input {"":1e700}. HARDENING note (report):
	// a handler using struct decode silently accepts request bodies whose unknown
	// or raw fields carry float64-overflowing number literals.
	"A-vs-M:schemaless-number-range": true,
}
