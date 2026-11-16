package jsonschema_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// This file fuzzes the whole exported API surface of the library,
// independently of any particular caller. Oracles are documented per
// target. The primary oracle everywhere is: no panic, no fatal
// (stack overflow, concurrent map access), no hang on any input,
// including the option combinations driven by a control byte.

// drafts used to drive the DefaultDraft option from fuzz input.
var fuzzDrafts = []*jsonschema.Draft{
	jsonschema.Draft4,
	jsonschema.Draft6,
	jsonschema.Draft7,
	jsonschema.Draft2019,
	jsonschema.Draft2020,
}

// newCompilerFromControl builds a compiler whose options are selected
// from a single control byte, so the fuzzer can explore the option
// matrix (DefaultDraft x AssertFormat x AssertContent x AssertVocabs).
func newCompilerFromControl(ctrl byte) *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(fuzzDrafts[int(ctrl>>4)%len(fuzzDrafts)])
	if ctrl&0x01 != 0 {
		c.AssertFormat()
	}
	if ctrl&0x02 != 0 {
		c.AssertContent()
	}
	if ctrl&0x04 != 0 {
		c.AssertVocabs()
	}
	return c
}

// FuzzUnmarshalJSON fuzzes jsonschema.UnmarshalJSON.
//
// Oracles:
//   - (a) no panic/hang on arbitrary bytes.
//   - (c) round trip / idempotence: if UnmarshalJSON accepts b, then
//     re-encoding the decoded value with encoding/json and decoding it
//     again must succeed and yield an equal value.
//
// Does NOT verify: exact agreement with encoding/json on acceptance
// (UnmarshalJSON is a thin wrapper over json.Decoder + a trailing-data
// check, so acceptance equals the stdlib by construction except for
// trailing bytes); numeric canonicalisation beyond json.Number.
func FuzzUnmarshalJSON(f *testing.F) {
	for _, s := range jsonCorpus {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return
		}
		// round trip: encode the decoded value and decode again.
		enc, err := json.Marshal(v)
		if err != nil {
			// A value produced by UnmarshalJSON must be json-encodable.
			t.Fatalf("json.Marshal of decoded value failed: %v (input=%q)", err, b)
		}
		v2, err := jsonschema.UnmarshalJSON(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("re-decode of re-encoded value failed: %v (input=%q, enc=%q)", err, b, enc)
		}
		enc2, err := json.Marshal(v2)
		if err != nil {
			t.Fatalf("json.Marshal of re-decoded value failed: %v", err)
		}
		// encode(decode(encode(x))) must be stable.
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("re-encode not idempotent:\n first=%q\nsecond=%q\ninput=%q", enc, enc2, b)
		}
	})
}

// FuzzCompile fuzzes the compilation core (Compiler.AddResource +
// Compiler.Compile, reaching compiler.go, objcompiler.go, draft.go,
// root.go, roots.go) with an arbitrary schema document and an
// option matrix selected from a control byte.
//
// Oracle: (a) no panic/hang/fatal for any schema document and any
// option combination. Compilation is expected to either succeed or
// return an error.
//
// Does NOT verify: that the compiled schema is semantically correct,
// nor bounded-work (super-linear time/alloc) guarantees.
func FuzzCompile(f *testing.F) {
	for _, s := range schemaCorpus {
		f.Add(byte(0), []byte(s))
	}
	f.Fuzz(func(t *testing.T, ctrl byte, schemaBytes []byte) {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
		if err != nil {
			return
		}
		c := newCompilerFromControl(ctrl)
		const url = "mem://fuzz/schema.json"
		if err := c.AddResource(url, doc); err != nil {
			return
		}
		_, _ = c.Compile(url)
	})
}

// FuzzValidate fuzzes the full compile+validate pipeline: an arbitrary
// schema document is compiled (with an option matrix) and an arbitrary
// instance document is validated against it.
//
// Oracles:
//   - (a) no panic/hang/fatal on any (schema, instance, options).
//   - determinism: validating the same instance twice yields the same
//     valid/invalid verdict, and Validate does not mutate its input.
//
// Does NOT verify: correctness of the validation verdict (no reference
// implementation is consulted here); bounded work.
func FuzzValidate(f *testing.F) {
	for _, sc := range schemaCorpus {
		for _, in := range instanceCorpus {
			f.Add(byte(0), []byte(sc), []byte(in))
		}
	}
	f.Fuzz(func(t *testing.T, ctrl byte, schemaBytes, instanceBytes []byte) {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
		if err != nil {
			return
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(instanceBytes))
		if err != nil {
			return
		}
		c := newCompilerFromControl(ctrl)
		const url = "mem://fuzz/schema.json"
		if err := c.AddResource(url, doc); err != nil {
			return
		}
		sch, err := c.Compile(url)
		if err != nil {
			return
		}

		// snapshot the instance to detect mutation by Validate.
		before, _ := json.Marshal(inst)

		err1 := sch.Validate(inst)

		after, _ := json.Marshal(inst)
		if !bytes.Equal(before, after) {
			t.Fatalf("Validate mutated its input:\nbefore=%q\nafter =%q", before, after)
		}

		// determinism: a second validation must give the same verdict.
		err2 := sch.Validate(inst)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic verdict: first=%v second=%v", err1, err2)
		}

		// if invalid, the standard output builders must not panic and
		// must be json-marshalable.
		if err1 != nil {
			if ve, ok := err1.(*jsonschema.ValidationError); ok {
				exerciseOutputs(t, ve)
			}
		}
	})
}

// exerciseOutputs drives the error-output API surface of
// ValidationError so it is covered by FuzzValidate.
func exerciseOutputs(t *testing.T, ve *jsonschema.ValidationError) {
	_ = ve.Error()
	_ = ve.GoString()
	if _, err := json.Marshal(ve.FlagOutput()); err != nil {
		t.Fatalf("marshal FlagOutput: %v", err)
	}
	if _, err := json.Marshal(ve.BasicOutput()); err != nil {
		t.Fatalf("marshal BasicOutput: %v", err)
	}
	if _, err := json.Marshal(ve.DetailedOutput()); err != nil {
		t.Fatalf("marshal DetailedOutput: %v", err)
	}
}

// builtin formats fuzzed by FuzzFormats. Keep in sync with format.go.
var builtinFormats = []string{
	"json-pointer", "relative-json-pointer", "uuid", "duration", "period",
	"ipv4", "ipv6", "hostname", "email", "date", "time", "date-time",
	"uri", "iri", "uri-reference", "iri-reference", "uri-template", "semver",
	"regex",
}

var (
	fmtSchemasOnce sync.Once
	fmtSchemas     map[string]*jsonschema.Schema
)

func formatSchemas(t *testing.T) map[string]*jsonschema.Schema {
	fmtSchemasOnce.Do(func() {
		fmtSchemas = map[string]*jsonschema.Schema{}
		for _, name := range builtinFormats {
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(
				`{"type":"string","format":"` + name + `"}`))
			if err != nil {
				t.Fatalf("seed schema for %q: %v", name, err)
			}
			c := jsonschema.NewCompiler()
			c.DefaultDraft(jsonschema.Draft7) // draft-07 asserts format by default
			c.AssertFormat()
			if err := c.AddResource("mem://fmt.json", doc); err != nil {
				t.Fatalf("add resource for %q: %v", name, err)
			}
			sch, err := c.Compile("mem://fmt.json")
			if err != nil {
				t.Fatalf("compile format schema %q: %v", name, err)
			}
			fmtSchemas[name] = sch
		}
	})
	return fmtSchemas
}

// FuzzFormats fuzzes every built-in format validator (format.go) by
// validating an arbitrary string against a `{"format":X}` schema with
// format assertion enabled.
//
// Oracle: (a) no panic/hang on any string for any built-in format;
// determinism of the verdict.
//
// Does NOT verify: that the accept/reject decision matches the format's
// RFC (no differential oracle against a reference parser is applied).
func FuzzFormats(f *testing.F) {
	seeds := []string{
		"", "a", "P1Y", "2006-01-02", "12:00:00Z", "2006-01-02T15:04:05Z",
		"a@b.c", "example.com", "::1", "127.0.0.1",
		"12345678-1234-1234-1234-123456789012", "1.2.3",
		"/a/b", "0#", "http://a/b", "urn:x", "*", "[", "P", "PT",
		strings.Repeat("9", 400), strings.Repeat(".", 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		schemas := formatSchemas(t)
		for _, name := range builtinFormats {
			sch := schemas[name]
			// must not panic; verdict itself is not asserted.
			err1 := sch.Validate(s)
			err2 := sch.Validate(s)
			if (err1 == nil) != (err2 == nil) {
				t.Fatalf("format %q non-deterministic on %q", name, s)
			}
		}
	})
}

// --- seed corpora -----------------------------------------------------

var jsonCorpus = []string{
	`null`, `true`, `false`, `0`, `-0`, `1.5`, `1e309`, `1e-400`,
	`123456789012345678901234567890`, `"str"`, `"x y"`, `""`,
	`[]`, `{}`, `[1,2,3]`, `{"a":1,"b":[true,null]}`,
	`{"a":1,"a":2}`,
	`   {"x":  "y"}   `, `[1,2,3] trailing`, `{} {}`,
	`{"nested":{"a":{"b":{"c":[1,[2,[3]]]}}}}`,
}

var schemaCorpus = []string{
	`true`, `false`, `{}`,
	`{"type":"object","properties":{"a":{"type":"integer"}},"required":["a"]}`,
	`{"type":"array","items":{"type":"string"},"minItems":1,"uniqueItems":true}`,
	`{"type":"string","pattern":"^a.*z$","minLength":1,"maxLength":10}`,
	`{"type":"number","minimum":0,"maximum":100,"multipleOf":2}`,
	`{"$ref":"#/$defs/x","$defs":{"x":{"type":"boolean"}}}`,
	`{"allOf":[{"type":"integer"}],"anyOf":[{"minimum":0}],"oneOf":[{"maximum":9}]}`,
	`{"if":{"type":"string"},"then":{"minLength":1},"else":{"type":"number"}}`,
	`{"type":"string","format":"email"}`,
	`{"type":"string","contentEncoding":"base64","contentMediaType":"application/json"}`,
	`{"$schema":"http://json-schema.org/draft-07/schema#","type":"null"}`,
	`{"$schema":"https://json-schema.org/draft/2020-12/schema","prefixItems":[{"type":"integer"}],"items":false}`,
	`{"$id":"mem://a","$ref":"mem://a"}`,
	`{"not":{"not":{"not":{}}}}`,
	`{"dependentRequired":{"a":["b"]},"dependentSchemas":{"a":{"required":["c"]}}}`,
	`{"propertyNames":{"pattern":"^[a-z]+$"},"patternProperties":{"^x":{"type":"integer"}}}`,
	`{"unevaluatedProperties":false,"unevaluatedItems":false}`,
	`{"enum":[1,"a",null,[1,2],{"k":"v"}],"const":42}`,
}

var instanceCorpus = []string{
	`null`, `true`, `42`, `-1`, `3.14`, `1e400`,
	`"hello"`, `""`, `"a@b.com"`, `[]`, `[1,2,3]`, `{}`,
	`{"a":1}`, `{"a":1,"b":2,"c":3}`, `[[[[[]]]]]`,
	`{"a":{"b":{"c":{"d":1}}}}`,
}
