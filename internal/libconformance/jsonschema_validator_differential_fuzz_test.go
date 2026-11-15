package libconformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	kin "github.com/getkin/kin-openapi/openapi3"
	santhosh "github.com/santhosh-tekuri/jsonschema/v6"
)

// diffSchemas are small schemas in the subset BOTH validators support, shaped
// after real Keyorix request constraints:
//
//   - "pat-create": the create-PAT body (object, required name, bounded string,
//     positive-integer ttl, closed object) — mirrors pat_handler.go.
//   - "role-enum": a role field constrained to a fixed enum — mirrors RBAC bodies.
//   - "string-array": a bounded array of strings — mirrors a scopes/list field.
//
// They deliberately avoid draft features the two dialects handle very differently
// ($ref, oneOf/anyOf discriminators, format assertions) so that a divergence is
// informative rather than a foregone dialect mismatch.
var diffSchemas = []struct {
	name string
	json string
}{
	{"pat-create", `{
		"type":"object",
		"required":["name"],
		"additionalProperties":false,
		"properties":{
			"name":{"type":"string","minLength":1,"maxLength":64},
			"ttl":{"type":"integer","minimum":1},
			"enabled":{"type":"boolean"}
		}
	}`},
	{"role-enum", `{
		"type":"object",
		"required":["role"],
		"properties":{
			"role":{"type":"string","enum":["admin","reader","writer"]}
		}
	}`},
	{"string-array", `{
		"type":"array",
		"items":{"type":"string"},
		"maxItems":10,
		"minItems":1
	}`},
}

type compiledPair struct {
	santhosh *santhosh.Schema
	kin      *kin.Schema
	compErr  error
}

var compileOnce sync.Once
var compiled []compiledPair

func compileDiffSchemas() []compiledPair {
	compileOnce.Do(func() {
		compiled = make([]compiledPair, len(diffSchemas))
		for i, s := range diffSchemas {
			var cp compiledPair

			c := santhosh.NewCompiler()
			doc, err := santhosh.UnmarshalJSON(bytes.NewReader([]byte(s.json)))
			if err != nil {
				cp.compErr = fmt.Errorf("santhosh unmarshal %s: %w", s.name, err)
				compiled[i] = cp
				continue
			}
			if err := c.AddResource("mem://"+s.name, doc); err != nil {
				cp.compErr = fmt.Errorf("santhosh addresource %s: %w", s.name, err)
				compiled[i] = cp
				continue
			}
			sch, err := c.Compile("mem://" + s.name)
			if err != nil {
				cp.compErr = fmt.Errorf("santhosh compile %s: %w", s.name, err)
				compiled[i] = cp
				continue
			}
			cp.santhosh = sch

			k := kin.NewSchema()
			if err := k.UnmarshalJSON([]byte(s.json)); err != nil {
				cp.compErr = fmt.Errorf("kin unmarshal %s: %w", s.name, err)
				compiled[i] = cp
				continue
			}
			cp.kin = k
			compiled[i] = cp
		}
	})
	return compiled
}

// FuzzJSONSchemaValidatorDifferential is a differential fuzz target over the two
// JSON-Schema validators present in the module cache:
//
//   - github.com/santhosh-tekuri/jsonschema/v6 — Keyorix's primary JSON-Schema
//     validator (live callers: internal/cryptoinventory validates the CBOM against
//     the vendored CycloneDX 1.6 schema; internal/egressguard uses it too).
//   - github.com/getkin/kin-openapi openapi3 — Keyorix's OpenAPI toolkit, whose
//     openapi3.Schema.VisitJSON validates instances against an OpenAPI-3 Schema
//     Object (live callers: server/http/handlers/contracttest, the OpenAPI
//     stateful fuzzer, internal/egressguard).
//
// They implement DIFFERENT dialects (JSON Schema draft vs OpenAPI 3.0 Schema
// Object), so a broad divergence set is expected; that is the point of the slide.
//
// Oracle (classified disagreement, never panic-only): for a fixed schema and a
// fuzzed instance, the two validators' VERDICTS (valid / invalid) must match,
// unless the divergence class is listed in jsonSchemaExpectedDiff. The class is
// (schemaName + instance-root-kind), coarse by design because the cause of a
// dialect divergence is rarely attributable to one keyword from the outside.
//
// Each validator decodes the instance its OWN idiomatic way (santhosh via
// jsonschema.UnmarshalJSON → json.Number; kin via encoding/json → float64). A
// split where exactly one validator's parser REJECTS the instance bytes is its
// own class, "instance-parse-split" — a genuine differential between the two
// JSON number/parse models.
func FuzzJSONSchemaValidatorDifferential(f *testing.F) {
	f.Add(byte(0), []byte(`{"name":"ok","ttl":5}`))
	f.Add(byte(0), []byte(`{"name":"","ttl":5}`))     // violates minLength
	f.Add(byte(0), []byte(`{"name":"ok","ttl":0}`))   // violates minimum
	f.Add(byte(0), []byte(`{"name":"ok","extra":1}`)) // additionalProperties:false
	f.Add(byte(0), []byte(`{"ttl":5}`))               // missing required name
	f.Add(byte(0), []byte(`{"name":"ok","ttl":1.5}`)) // non-integer ttl
	f.Add(byte(0), []byte(`{"name":"ok","ttl":2.0}`)) // integer-valued float
	f.Add(byte(1), []byte(`{"role":"admin"}`))
	f.Add(byte(1), []byte(`{"role":"root"}`)) // not in enum
	f.Add(byte(1), []byte(`{"role":5}`))      // wrong type
	f.Add(byte(2), []byte(`["a","b"]`))
	f.Add(byte(2), []byte(`[]`))      // minItems
	f.Add(byte(2), []byte(`["a",1]`)) // item type
	f.Add(byte(2), []byte(`"notarray"`))

	pairs := compileDiffSchemas()
	for i, p := range pairs {
		if p.compErr != nil {
			f.Fatalf("schema %d failed to compile in both validators: %v", i, p.compErr)
		}
	}

	f.Fuzz(func(t *testing.T, sel byte, instance []byte) {
		if len(instance) > 1<<14 {
			return
		}
		p := pairs[int(sel)%len(pairs)]
		schemaName := diffSchemas[int(sel)%len(pairs)].name

		// Decode for santhosh (its own parser, json.Number-preserving).
		vS, errSparse := santhosh.UnmarshalJSON(bytes.NewReader(instance))
		// Decode for kin (encoding/json, float64 numbers).
		var vK any
		errKparse := json.Unmarshal(instance, &vK)

		parsedS := errSparse == nil
		parsedK := errKparse == nil
		if parsedS != parsedK {
			// The two instance decoders are DIFFERENT JSON parsers:
			// santhosh's jsonschema.UnmarshalJSON preserves numbers as json.Number
			// (unbounded) and REJECTS duplicate object keys; kin decodes via
			// encoding/json, which materializes numbers into float64 (range-bounded)
			// and keeps last-wins on duplicate keys. A parse split is therefore a
			// property of the parsers, not of the schema — classify by cause.
			class := classifyParseSplit(parsedS, parsedK, errSparse, errKparse)
			if !jsonSchemaExpectedDiff[class] {
				t.Fatalf("NEW instance-parse disagreement [class=%q]\n  schema=%s\n  instance=%q\n  santhosh parsed=%v err=%v\n  kin      parsed=%v err=%v",
					class, schemaName, instance, parsedS, errSparse, parsedK, errKparse)
			}
			return
		}
		if !parsedS {
			return // both failed to parse the instance — nothing to validate.
		}

		validS := p.santhosh.Validate(vS) == nil
		validK := p.kin.VisitJSON(vK) == nil

		if validS != validK {
			class := fmt.Sprintf("verdict:%s:%s", schemaName, rootKind(vK))
			if !jsonSchemaExpectedDiff[class] {
				t.Fatalf("NEW verdict disagreement [class=%q]\n  schema=%s\n  instance=%q\n  santhosh valid=%v\n  kin      valid=%v",
					class, schemaName, instance, validS, validK)
			}
		}
	})
}

// classifyParseSplit names the cause of a one-sided instance-parse failure
// between santhosh (json.Number-preserving, duplicate-key-rejecting) and kin
// (encoding/json: float64 numbers, last-wins duplicates).
func classifyParseSplit(parsedS, parsedK bool, errS, errK error) string {
	if parsedS && !parsedK {
		// santhosh accepted, kin (encoding/json) rejected.
		m := ""
		if errK != nil {
			m = errK.Error()
		}
		if containsAny(m, "cannot unmarshal number", "overflow") {
			return "parse-split:kin-float64-number-range" // number too big for float64
		}
		return "parse-split:kin-rejects:other"
	}
	// kin accepted, santhosh rejected.
	m := ""
	if errS != nil {
		m = errS.Error()
	}
	if containsAny(m, "duplicate") {
		return "parse-split:santhosh-duplicate-key"
	}
	return "parse-split:santhosh-rejects:other"
}

func rootKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64, json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "other"
	}
}
