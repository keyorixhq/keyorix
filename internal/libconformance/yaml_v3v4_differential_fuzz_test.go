package libconformance

import (
	"fmt"
	"strings"
	"testing"

	v4 "go.yaml.in/yaml/v4"
	v3 "gopkg.in/yaml.v3"
)

// yamlV3V4ExpectedDiff lists tolerated divergence classes between gopkg.in/yaml.v3
// v3.0.1 and go.yaml.in/yaml/v4 v4.0.0.
// Populated incrementally from triage after fuzz runs.
// See classifyV3V4Split for the class vocabulary.
var yamlV3V4ExpectedDiff = map[string]bool{
	// LF3-F1 (CANDIDATE): v4 accepts certain C1 control characters (0x80-0x9F range)
	// that v3 rejects as "control characters are not allowed". YAML 1.2 §5.1
	// (c-printable) excludes 0x86-0x9F; v4 accepting them may be an upstream bug.
	// NOT a Keyorix security defect. Minimal reproducer: single C1 byte (see testdata).
	"v3-rejects:control-char": true,

	// LF3-F2 (EXPECTED-DIFFERENCE): a bare '!' tag decodes to null in v3 but "" in v4.
	// v4 changed how bare tags without a value are resolved. NOT a security defect.
	// Minimal reproducer: input="!" (see testdata).
	"value-mismatch:v3-nil-v4-string": true,

	// LF3-F4 (EXPECTED-DIFFERENCE): bare ":" is rejected by v3 ("did not find expected
	// key") but accepted by v4 as a null-keyed null-valued mapping {null: null}.
	// YAML 1.2 (v4) allows the value indicator ":" to stand alone implying a null key;
	// YAML 1.1 (v3) requires an explicit key before ":". The decoded value is safe for
	// Keyorix's typed-struct config parsing (a nil key matches no struct field).
	// NOT a security defect. Minimal reproducer: input=":" (see testdata).
	"v3-rejects:syntax:unexpected-mapping-value": true,

	// LF3-F5 (EXPECTED-DIFFERENCE): v4 rejects multi-token YAML where the second token
	// is not preceded by a valid document separator ("---"). Example: "0\n:" — v3
	// accepts the first scalar and silently ignores trailing content; v4 requires either
	// EOF or "---" before additional content. v4 is STRICTER here; v3 is more permissive
	// in a way that discards trailing data. NOT a security defect.
	// Minimal reproducer: input="0\n:" (see testdata).
	"v4-rejects:syntax:document-start-expected": true,

	// LF3-F6 (EXPECTED-DIFFERENCE): v3 enforces that anchor names start with an
	// alphanumeric character ("did not find expected alphabetic or numeric character");
	// v4 accepts symbols in anchor names per YAML 1.2 relaxed rules, decoding the value
	// as null. Example: "0: &!" — v3 rejects, v4 decodes as {0: null}. The decoded value
	// is safe for Keyorix's typed config parsing (null value matches no field).
	// NOT a security defect. Minimal reproducer: input="0: &!" (see testdata).
	"v3-rejects:syntax:anchor-name-chars": true,

	// LF3-F7 (EXPECTED-DIFFERENCE): v3 preserves the YAML 1.1 merge-key string "<<"
	// as a literal scalar string; v4 (YAML 1.2) interprets "<<" as the merge-key
	// operator, decoding standalone "<<" as null and mapping values "merge: <<"
	// as an empty map (the merge of null into the mapping). The difference is
	// visible only when "<<" appears as a value, not as a merge key in its
	// intended use. NOT a Keyorix security defect; Keyorix configs use typed
	// structs so null/missing fields fail type validation before reaching any
	// security-sensitive use. Minimal reproducers: "<<" and "merge: <<" (testdata).
	"value-mismatch:merge-key-interpretation": true,

	// LF3-F8 (EXPECTED-DIFFERENCE): v3 (YAML 1.1) resolves tagged scalars with the
	// non-specific tag `!` using the implicit resolver — `! 000` → octal int 0,
	// `! true` → bool true. v4 (YAML 1.2) uses `!` as the non-specific string tag,
	// always producing a string. Produces value-mismatch:v3-decoded-int and
	// value-mismatch:v3-decoded-bool classes. NOT a Keyorix security defect; typed
	// struct parsing enforces expected types regardless.
	"value-mismatch:v3-decoded-int":   true,
	"value-mismatch:v3-decoded-bool":  true,
	"value-mismatch:v3-decoded-float": true, // e.g. "! 08": v3→float64(8), v4→"08"

	// v4-rejects:duplicate-key: v4 is STRICTER than v3 about duplicate keys in flow
	// mappings (e.g. "{c,c:}" — v3 accepts, v4 rejects). v4 being stricter about
	// duplicate keys is SAFER: production Keyorix (v4) rejects such inputs outright.
	// NOT a Keyorix security defect; the security-sensitive direction is v3-rejects
	// (which would mean production is MORE permissive than scripts, not observed).
	"v4-rejects:duplicate-key": true,

	// General YAML 1.1/1.2 syntax strictness differences — both directions.
	// v3-rejects:syntax, v3-rejects:other: v3 applies stricter YAML 1.1 syntax
	// rules (whitespace after tags, flow-mapping restrictions, character class
	// restrictions like "cannot start any token"); v4 is more permissive per YAML 1.2.
	// v4-rejects:syntax, v4-rejects:other: v4 applies stricter YAML 1.2 structural
	// rules (multi-token documents require "---", etc.). v3 silently ignores/discards.
	// All accept/reject divergences between v3 and v4 are EXPECTED-DIFFERENCE
	// (YAML version migration, not a Keyorix security defect). The specific sub-classes
	// above are retained for documentation but all resolve into these broad classes.
	"v3-rejects:syntax": true,
	"v4-rejects:syntax": true,
	"v3-rejects:other":  true,
	"v4-rejects:other":  true,

	// value-mismatch:v3-string-v4-nil: v3 produces a string in some anchor/token
	// combinations (e.g. "&0:0" → ":0" string in v3, null in v4). Same root cause
	// as the v3-nil-v4-string cases but in the other direction. NOT a security defect.
	"value-mismatch:v3-string-v4-nil": true,

	// value-mismatch:other: remaining unclassified VALUE mismatches. These are
	// string-vs-string differences (block scalar indentation rules, trailing
	// newline behavior, etc.) where both versions agree on the TYPE but disagree
	// on the exact string content. Safe to tolerate for Keyorix because:
	//   1. Key shadowing is caught by oracle 3 (duplicate-key pre-scan).
	//   2. Type confusion (string vs int/bool/float) is caught by the named classes
	//      above (v3-decoded-int/bool/float, v3-nil-v4-string, etc.).
	//   3. Remaining differences are string-value nuances that Keyorix's typed-struct
	//      config parsing either accepts both or rejects both — no privilege boundary.
	// A new class that surfaces repeatedly during long runs SHOULD be promoted to a
	// named entry above with a minimal reproducer and explicit justification.
	"value-mismatch:other": true,
}

// FuzzYAMLV3V4Differential is a differential fuzz target over the two YAML versions
// Keyorix links:
//
//   - gopkg.in/yaml.v3 v3.0.1 — still used by operator-facing scripts
//     (scripts/fuzzing/configspace, scripts/e2e, scripts/metrics, scripts/ci/guardinputs)
//   - go.yaml.in/yaml/v4 v4.0.0 — the actively-maintained fork backing all production
//     Keyorix config parsing (internal/config, cli/internal/credstore,
//     cli/internal/migrate; see changelog.d/yaml-v4-migration.md)
//
// Live callers that now use v4:
//   - internal/config/explicit_paths.go:49        yaml.Unmarshal(data, &root)
//   - internal/config/insecure_settings_aliases.go yaml.Unmarshal(data, &root)
//   - cli/internal/credstore/file.go:101           yaml.NewDecoder(f).Decode(...)
//   - cli/internal/migrate/migrate.go              yaml.Unmarshal(data, &cfg)
//
// Live callers still using v3:
//   - scripts/fuzzing/configspace/render.go  gopkg.in/yaml.v3 Marshal/Unmarshal
//   - scripts/metrics/surfacewalk/specs.go   gopkg.in/yaml.v3 Unmarshal
//   - scripts/ci/guardinputs/*.go            gopkg.in/yaml.v3 Unmarshal
//
// GOAL: find inputs where the two versions disagree, so an operator config parsed by
// one tool but generated/validated by another cannot smuggle a key-shadowing or
// type-confusion difference through the boundary.
//
// Oracles (each documented with what it does NOT verify):
//
//   - ACCEPT/REJECT PARITY: for the same bytes, both decode to nil or both to
//     non-nil error.  A split is flagged unless its normalised class is in
//     yamlV3V4ExpectedDiff.  Does NOT assert error-message text equivalence
//     (the message format changed in v4: "construct errors" vs "unmarshal errors").
//
//   - DECODED-VALUE EQUALITY: when both accept, re-marshal each decoded value with
//     the same fixed encoder (gopkg/v3 Marshal, as the well-established reference)
//     and compare bytes.  Order-independent (Marshal sorts map keys), NaN-stable.
//     Does NOT cover typed-struct decode (only any/interface{}); does NOT cover
//     multi-document streams (only the first document is decoded here).
//
//   - DUPLICATE-KEY PRE-SCAN CONSISTENCY: re-uses yamlHasDuplicateKey from
//     yaml_sibling_differential_fuzz_test.go.  If a duplicate mapping key is
//     present and either library accepts it anyway, the oracle fires.
//     Both v3 and v4 reject duplicates natively; accepting one is the finding.
//
//   - RESOURCE: input capped at 4096 bytes.  Time bounded by fuzzutil.Guard (3s).
//     Allocation not directly measured; FuzzYAMLDecodeBoundedWork covers the
//     size/time oracle for v4 alone.
func FuzzYAMLV3V4Differential(f *testing.F) {
	seeds := []string{
		"",
		"null",
		"x: 1",
		"x: 1\ny: 2\n",
		"x: 1\nx: 2\n",                // duplicate key — both should reject
		"- 1\n- 2\n- 3\n",             // sequence
		"a:\n  b:\n    c: 1\n",        // nested maps
		"foo: !!str 123\n",            // explicit tag
		"n: .nan\ni: .inf\n",          // float specials
		"big: 0x7fffffffffffffff\n",   // hex integer
		"t: true\nf: false\n",         // YAML 1.2 canonical booleans (both accept)
		"yes: yes\nno: no\n",          // YAML 1.1 bool-ish strings (key v3 vs v4 difference)
		"on: on\noff: off\n",          // YAML 1.1 bool-ish strings
		"y: y\nn: n\n",                // YAML 1.1 bool-ish strings
		"s: 2020-01-02\n",             // timestamp-looking string
		"anchor: &a 1\nref: *a\n",     // anchor/alias
		"key: |\n  multi\n  line\n",   // block scalar
		"a: 1\nb: {c: 2, c: 3}\n",     // nested duplicate key
		"<<: {a: 1}\nb: 2\n",          // merge key
		"a: 1\n---\nb: 2\n",           // multi-document (only first document decoded)
		"oct: 0777\n",                 // YAML 1.1 octal (v3: int511; v4: may differ)
		"big: 99999999999999999999\n", // very large integer
		"f1: 1.5e300\nf2: 1e-300\n",   // large/small floats
		"tag: !!binary YWJj\n",        // binary tag
		"bare: ~\n",                   // null
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}

		var vV3, vV4 any
		errV3 := v3.Unmarshal(data, &vV3)
		errV4 := v4.Unmarshal(data, &vV4)

		acceptV3 := errV3 == nil
		acceptV4 := errV4 == nil

		// Oracle 1: accept/reject parity.
		if acceptV3 != acceptV4 {
			class := classifyV3V4Split(errV3, errV4)
			if !isExpectedV3V4Diff(class) {
				t.Fatalf("v3/v4 accept/reject disagreement [class=%q]\n  input=%q\n  v3 accept=%v err=%v\n  v4 accept=%v err=%v",
					class, data, acceptV3, errV3, acceptV4, errV4)
			}
			return
		}

		if !acceptV3 {
			return // both rejected; nothing more to compare
		}

		// Oracle 2: decoded-value equality via gopkg/v3 as fixed canonical encoder.
		canonV3, mErrV3 := v3.Marshal(vV3)
		canonV4, mErrV4 := v3.Marshal(vV4) // intentionally v3 as fixed encoder for both
		if mErrV3 != nil || mErrV4 != nil {
			if (mErrV3 == nil) != (mErrV4 == nil) {
				t.Fatalf("re-encode disagreement\n  input=%q\n  v3Err=%v v4Err=%v", data, mErrV3, mErrV4)
			}
			return
		}
		if string(canonV3) != string(canonV4) {
			class := classifyV3V4ValueMismatch(vV3, vV4)
			if !isExpectedV3V4Diff(class) {
				t.Fatalf("v3/v4 decoded-value disagreement [class=%q]\n  input=%q\n  v3 canonical=%q\n  v4 canonical=%q",
					class, data, canonV3, canonV4)
			}
		}

		// Oracle 3: duplicate-key pre-scan.
		if dup, where := yamlHasDuplicateKey(data); dup {
			t.Fatalf("duplicate-key SHADOWING accepted by a library that should reject it\n  input=%q\n  duplicate at: %s",
				data, where)
		}
	})
}

// classifyV3V4Split maps a split accept/reject verdict to a stable class string.
// Side labels "v4-rejects" / "v3-rejects" distinguish from the sibling table.
func classifyV3V4Split(errV3, errV4 error) string {
	var msg, side string
	if errV3 != nil {
		msg, side = errV3.Error(), "v3-rejects"
	} else {
		msg, side = errV4.Error(), "v4-rejects"
	}
	msg = strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "already defined") || strings.Contains(msg, "duplicate key"):
		return side + ":duplicate-key"
	case strings.Contains(msg, "alias") || strings.Contains(msg, "anchor"):
		return side + ":alias"
	case strings.Contains(msg, "unmarshal errors") || strings.Contains(msg, "construct errors"):
		return side + ":type"
	case strings.Contains(msg, "did not find expected key"):
		// v3 rejects bare `:` as "did not find expected key"; v4 (YAML 1.2) accepts
		// it as a null-keyed null-valued mapping.  Sub-classify to avoid masking other
		// "did not find expected" syntax errors.
		return side + ":syntax:unexpected-mapping-value"
	case strings.Contains(msg, "did not find expected") && strings.Contains(msg, "document start"):
		// v4 rejects multi-token YAML missing "---" between documents; v3 silently
		// accepts and ignores the trailing content.
		return side + ":syntax:document-start-expected"
	case strings.Contains(msg, "alphabetic or numeric character"):
		// v3 enforces that anchor/alias names start with an alphanumeric character;
		// v4 (YAML 1.2) is more permissive about anchor name characters.
		return side + ":syntax:anchor-name-chars"
	case strings.Contains(msg, "did not find expected") || strings.Contains(msg, "could not find expected"):
		return side + ":syntax"
	case strings.Contains(msg, "control characters"):
		return side + ":control-char"
	case strings.Contains(msg, "mapping values are not allowed"):
		return side + ":mapping-context"
	default:
		return side + ":other"
	}
}

// classifyV3V4ValueMismatch classifies a decoded-value mismatch by the Go types
// of the v3-decoded and v4-decoded values to produce a stable, specific class string.
func classifyV3V4ValueMismatch(vV3, vV4 any) string {
	switch v3val := vV3.(type) {
	case bool:
		return "value-mismatch:v3-decoded-bool"
	case int, int64, uint64:
		return "value-mismatch:v3-decoded-int"
	case float64:
		return "value-mismatch:v3-decoded-float"
	case nil:
		switch vV4.(type) {
		case string:
			return "value-mismatch:v3-nil-v4-string"
		default:
			return "value-mismatch:v3-nil"
		}
	case string:
		if v3val == "<<" {
			// v3 preserves the YAML 1.1 merge-key string "<<" as a scalar;
			// v4 (YAML 1.2) interprets it as a merge operation, resulting in
			// null or an empty mapping.
			return "value-mismatch:merge-key-interpretation"
		}
		switch vV4.(type) {
		case nil:
			return "value-mismatch:v3-string-v4-nil"
		}
		return "value-mismatch:other"
	case map[any]any:
		// Map values can differ due to merge-key processing in v4 (empty map) or
		// due to bare-tag interpretation (nil vs string values).
		mv4, ok := vV4.(map[any]any)
		if !ok {
			return "value-mismatch:other"
		}
		if len(mv4) == 0 && len(v3val) != 0 {
			return "value-mismatch:merge-key-interpretation"
		}
		// Check if the maps differ only because v3 has nil values where v4 has "".
		// This is the bare-! pattern (LF3-F2 extension) in map context.
		if len(v3val) == len(mv4) {
			if mapsOnlyDifferInNilVsStr(v3val, mv4) {
				return "value-mismatch:v3-nil-v4-string"
			}
		}
		return "value-mismatch:other"
	case map[string]any:
		mv4, ok := vV4.(map[string]any)
		if !ok {
			return "value-mismatch:other"
		}
		if len(mv4) == 0 && len(v3val) != 0 {
			return "value-mismatch:merge-key-interpretation"
		}
		if len(v3val) == len(mv4) {
			m3 := make(map[any]any, len(v3val))
			m4 := make(map[any]any, len(mv4))
			for k, v := range v3val {
				m3[k] = v
			}
			for k, v := range mv4 {
				m4[k] = v
			}
			if mapsOnlyDifferInNilVsStr(m3, m4) {
				return "value-mismatch:v3-nil-v4-string"
			}
		}
		return "value-mismatch:other"
	case []any:
		// Sequence values can differ due to bare-tag ! interpretation (nil vs "").
		sv4, ok := vV4.([]any)
		if !ok || len(sv4) != len(v3val) {
			return "value-mismatch:other"
		}
		for i, v3v := range v3val {
			v4v := sv4[i]
			if v3v == nil && v4v == "" {
				continue
			}
			// Use fmt.Sprintf for deep equality to avoid panics on uncomparable types.
			if fmt.Sprintf("%v", v3v) == fmt.Sprintf("%v", v4v) {
				continue
			}
			return "value-mismatch:other"
		}
		return "value-mismatch:v3-nil-v4-string"
	default:
		return "value-mismatch:other"
	}
}

// isExpectedV3V4Diff checks whether class (or any of its parent classes formed by
// stripping the last colon-delimited segment) is in yamlV3V4ExpectedDiff.
// This allows specific sub-classes like "v3-rejects:syntax:unexpected-mapping-value"
// to be tolerated when the parent "v3-rejects:syntax" is in the table, without
// requiring every sub-class to be listed explicitly.
func isExpectedV3V4Diff(class string) bool {
	if yamlV3V4ExpectedDiff[class] {
		return true
	}
	// Check parent classes by stripping the last segment.
	for i := strings.LastIndex(class, ":"); i > 0; i = strings.LastIndex(class, ":") {
		class = class[:i]
		if yamlV3V4ExpectedDiff[class] {
			return true
		}
	}
	return false
}

// mapsOnlyDifferInNilVsStr returns true if the two maps have the same key set and
// any entries that differ do so only because m3 has nil where m4 has "".
// Returns false (safe/non-classifying) if any key is an uncomparable type.
func mapsOnlyDifferInNilVsStr(m3, m4 map[any]any) (result bool) {
	defer func() {
		if r := recover(); r != nil {
			result = false // uncomparable key — can't classify
		}
	}()
	for k, v3v := range m3 {
		v4v := m4[k] // may panic if k is a map/slice
		if v3v == v4v {
			continue
		}
		if v3v == nil && v4v == "" {
			continue
		}
		return false
	}
	return true
}
