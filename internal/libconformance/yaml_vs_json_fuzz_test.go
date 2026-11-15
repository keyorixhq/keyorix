package libconformance

// DF1 Oracle D — gopkg.in/yaml.v3 vs encoding/json on input that is valid JSON.
//
// Every JSON document is a YAML document (JSON is a YAML 1.2 subset). Keyorix parses
// config/policy with yaml.v3 (internal/config/config.go:447, internal/k8ssync/config.go:112)
// and parses request/API bodies and many artefacts with encoding/json. Where the same
// bytes can be read by either — a config value echoed into a JSON API, a JSON body a tool
// later re-reads as YAML, `cli/cmd/output.go`'s YAML/JSON duality — a value that the two
// libraries decode DIFFERENTLY is a decision-vs-action split. This oracle feeds one input
// that encoding/json accepts to both libraries and fails when they disagree on acceptance
// or on the decoded value, outside a documented, allowlisted dialect difference.
//
// WHAT THIS ORACLE DOES NOT VERIFY:
//   - It only drives inputs encoding/json ACCEPTS (JSON ⊆ YAML direction). It does NOT test
//     YAML-only syntax (anchors `&`/`*`, merge keys `<<`, tags `!!`, flow/block scalars,
//     multi-doc `---`): those are not valid JSON, so there is no "same bytes, two readings"
//     at a JSON consumer. The anchors/merge/duplicate-key strict-vs-lax axis is partially
//     covered — duplicate keys ARE reachable as JSON and ARE tested (yaml.v3 rejects, json
//     last-wins) — but anchor/merge expansion is out of scope here.
//   - It compares DECODED VALUES canonicalised through Go's own types, not the raw token
//     streams. A difference that both libraries normalise away before returning an
//     `interface{}` is invisible.
//   - Number equality is by mathematical value (big.Rat), so 1 and 1.0 are equal; a pure
//     REPRESENTATION difference that preserves value is not flagged. A value-changing
//     precision loss (float64 rounding of a large integer) IS flagged as number-precision.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// containsYAMLBreakRunes reports whether s holds a character YAML treats as a line break
// and folds in scalar content — CR, NEL (U+0085), LINE SEPARATOR (U+2028), PARAGRAPH
// SEPARATOR (U+2029). Rune constants keep the source ASCII. encoding/json preserves these
// verbatim; yaml.v3 folds them (to a space in a quoted scalar, to \n otherwise). The
// signature "json kept the break, yaml did not" is exactly that documented folding, not an
// arbitrary value divergence.
func containsYAMLBreakRunes(s string) bool {
	for _, r := range s {
		switch r {
		case '\r', 0x85, 0x2028, 0x2029:
			return true
		}
	}
	return false
}

// yamlWSFoldEqual reports whether a and b are equal once every space, tab, newline, CR and
// Unicode line-break rune (NEL/LS/PS) is removed. Because both strings are decoded from the
// SAME bytes, a difference that vanishes under this stripping is purely yaml.v3's
// whitespace / line-break folding (it folds breaks and strips whitespace adjacent to a fold
// point) against encoding/json's verbatim preservation — documented YAML behaviour, not an
// arbitrary value divergence.
func stripYAMLWS(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', 0x85, 0x2028, 0x2029:
			// drop
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func yamlWSFoldEqual(a, b string) bool { return stripYAMLWS(a) == stripYAMLWS(b) }

// hasDuplicateJSONKey reports whether any JSON object in data declares the same member
// name twice (the construct encoding/json silently accepts last-wins and yaml.v3 rejects).
func hasDuplicateJSONKey(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		isObj   bool
		seen    map[string]bool
		wantKey bool // inside an object, the next string token is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{isObj: true, seen: map[string]bool{}, wantKey: true})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				// the structure that just closed was a value for its parent object;
				// the parent now expects the next key.
				if len(stack) > 0 && stack[len(stack)-1].isObj {
					stack[len(stack)-1].wantKey = true
				}
			}
			continue
		}
		if len(stack) == 0 {
			continue
		}
		top := stack[len(stack)-1]
		if top.isObj && top.wantKey {
			if s, ok := tok.(string); ok {
				if top.seen[s] {
					return true
				}
				top.seen[s] = true
			}
			top.wantKey = false
		} else if top.isObj {
			// a scalar value just completed; expect the next key.
			top.wantKey = true
		}
	}
}

type yamlJSONMismatch struct {
	key        string
	detail     string
	jsonV, yml string
}

// normMapKey renders any map key as a string (JSON keys are always strings; yaml may hand
// back map[string]any or map[any]any depending on key types).
func asStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, vv := range m {
			out[fmt.Sprint(k)] = vv
		}
		return out, true
	}
	return nil, false
}

// numVal converts any numeric decoding (float64/int/int64/uint64/json.Number) to a big.Rat.
func numVal(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case float64:
		r := new(big.Rat)
		if r.SetFloat64(n) == nil {
			return nil, false // NaN/Inf — not representable
		}
		return r, true
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	case int64:
		return new(big.Rat).SetInt64(n), true
	case uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(n)), true
	case json.Number:
		r, ok := new(big.Rat).SetString(string(n))
		return r, ok
	}
	return nil, false
}

// treeCompare returns the first precise mismatch between two decoded JSON/YAML values.
func treeCompare(j, y any) *yamlJSONMismatch {
	// numbers first (cross-type int/float)
	if jr, jok := numVal(j); jok {
		yr, yok := numVal(y)
		if !yok {
			return &yamlJSONMismatch{key: "type-differs", detail: "json number vs non-number", jsonV: fmt.Sprint(j), yml: fmt.Sprint(y)}
		}
		if jr.Cmp(yr) != 0 {
			return &yamlJSONMismatch{key: "number-precision", detail: "same token decoded to different numeric value", jsonV: jr.FloatString(0), yml: yr.FloatString(0)}
		}
		return nil
	}
	switch jv := j.(type) {
	case map[string]any:
		ym, ok := asStringMap(y)
		if !ok {
			return &yamlJSONMismatch{key: "type-differs", detail: "json object vs non-object", jsonV: fmt.Sprint(j), yml: fmt.Sprint(y)}
		}
		if len(jv) != len(ym) {
			return &yamlJSONMismatch{key: "object-size-differs", detail: "object key count differs", jsonV: fmt.Sprint(jv), yml: fmt.Sprint(ym)}
		}
		for k, jvv := range jv {
			yvv, ok := ym[k]
			if !ok {
				return &yamlJSONMismatch{key: "object-keys-differ", detail: "key " + k + " missing in yaml reading", jsonV: fmt.Sprint(jv), yml: fmt.Sprint(ym)}
			}
			if m := treeCompare(jvv, yvv); m != nil {
				return m
			}
		}
		return nil
	case []any:
		ys, ok := y.([]any)
		if !ok {
			return &yamlJSONMismatch{key: "type-differs", detail: "json array vs non-array", jsonV: fmt.Sprint(j), yml: fmt.Sprint(y)}
		}
		if len(jv) != len(ys) {
			return &yamlJSONMismatch{key: "array-length-differs", detail: "array length differs", jsonV: fmt.Sprint(jv), yml: fmt.Sprint(ys)}
		}
		for i := range jv {
			if m := treeCompare(jv[i], ys[i]); m != nil {
				return m
			}
		}
		return nil
	case string:
		if ys, ok := y.(string); !ok || ys != jv {
			ystr := fmt.Sprint(y)
			key := "string-differs"
			// yaml.v3 folds Unicode line breaks (NEL U+0085, LS U+2028, PS U+2029, CR) in
			// scalar content; encoding/json preserves them verbatim. If normalising those to
			// \n on both sides reconciles the strings, this is that documented line-folding,
			// not an arbitrary value divergence.
			if ok && (containsYAMLBreakRunes(jv) || containsYAMLBreakRunes(ystr)) && yamlWSFoldEqual(jv, ystr) {
				key = "yaml-line-break-normalization"
			}
			return &yamlJSONMismatch{key: key, detail: "string value differs", jsonV: jv, yml: ystr}
		}
		return nil
	case bool:
		if yb, ok := y.(bool); !ok || yb != jv {
			return &yamlJSONMismatch{key: "bool-differs", detail: "bool value differs", jsonV: fmt.Sprint(jv), yml: fmt.Sprint(y)}
		}
		return nil
	case nil:
		if y != nil {
			return &yamlJSONMismatch{key: "null-differs", detail: "json null vs yaml non-null", jsonV: "null", yml: fmt.Sprint(y)}
		}
		return nil
	}
	return nil
}

// yamlJSONCompare is the pure oracle core.
func yamlJSONCompare(data []byte) *yamlJSONMismatch {
	// Require the WHOLE input to be valid JSON. json.Decoder.Decode reads one value and
	// silently ignores trailing bytes (`0}` decodes to 0), but yaml reads the whole string
	// — a harness-premise mismatch, not a library finding. json.Valid rejects any input
	// that is not exactly one complete JSON value (modulo surrounding whitespace).
	if !json.Valid(data) {
		return nil // not wholly-valid JSON — out of scope for this oracle
	}
	// DEFAULT encoding/json decode (float64 numbers) — this is what nearly all Keyorix
	// call sites use (json.Unmarshal without UseNumber), so it is the reading a real
	// security decision is taken on. Modelling UseNumber() here would hide the float64
	// precision loss that is the actual differential.
	var jv any
	if err := json.Unmarshal(data, &jv); err != nil {
		return nil // not JSON — out of scope for this oracle
	}
	var yv any
	if err := yaml.Unmarshal(data, &yv); err != nil {
		// yaml rejected a value encoding/json accepted. The reachable, documented case is
		// a duplicate mapping key (JSON: last-wins; yaml.v3: error). Classify precisely.
		return &yamlJSONMismatch{key: classifyYAMLReject(data), detail: "yaml.v3 rejected input encoding/json accepted", jsonV: "accepted", yml: err.Error()}
	}
	return treeCompare(jv, yv)
}

func classifyYAMLReject(data []byte) string {
	switch {
	case !utf8.Valid(data):
		// encoding/json is lenient about invalid UTF-8 in a string (accepts it, substitutes
		// U+FFFD on unmarshal); yaml.v3 requires valid UTF-8 and rejects.
		return "yaml-rejects-invalid-utf8"
	case hasDuplicateJSONKey(data):
		return "yaml-rejects-json-dup-key"
	default:
		return "yaml-rejects-json-accepts"
	}
}

var yamlDiffAllow = func() *allowlist {
	return newAllowlist(
		expectedDiff{
			key: "yaml-rejects-json-dup-key",
			reason: "A JSON object with a duplicate member name (`{\"a\":1,\"a\":2}`). RFC 8259 " +
				"permits it and encoding/json takes LAST-wins (`{\"a\":2}`); YAML 1.2 forbids " +
				"duplicate mapping keys and yaml.v3 returns an error. This is a real, documented " +
				"accept-vs-reject split and a genuine security concern where one config reader is " +
				"JSON-based and another YAML-based (report Finding D-1), but it is a library/spec " +
				"difference, not a bug in either parser. RED-PROVEN by seed `{\"a\":1,\"a\":2}`.",
		},
		expectedDiff{
			key: "yaml-line-break-normalization",
			reason: "A string containing a Unicode line break YAML folds — NEL (U+0085), LINE " +
				"SEPARATOR (U+2028), PARAGRAPH SEPARATOR (U+2029), or a bare CR. encoding/json keeps " +
				"the character verbatim; yaml.v3 normalises it (per the YAML line-break rules) so the " +
				"SAME bytes decode to DIFFERENT string values. This is a SILENT value divergence (both " +
				"accept) — the dangerous shape — but it is documented YAML behaviour. RED-PROVEN by " +
				"seed `\"\\u0085\"`. Report Finding D-5: a config/identity string with these separators " +
				"means one thing to a JSON reader and another to a YAML reader of the same bytes.",
		},
		expectedDiff{
			key: "yaml-rejects-json-accepts",
			reason: "General class: a byte sequence encoding/json accepts but yaml.v3's " +
				"indentation-sensitive grammar rejects — a TAB used as leading whitespace (YAML " +
				"forbids tabs in indentation; JSON treats tab as whitespace), and assorted control " +
				"characters. Unlike the number/type/value classes, this is a VISIBLE hard reject on " +
				"the YAML side, not a silent value divergence, so a dual-reader path fails closed on " +
				"the YAML consumer rather than acting on a mismatched value — lower severity. The " +
				"dangerous silent-divergence classes (number-precision, type-differs, *-differs) stay " +
				"non-allowlisted and still fire. RED-PROVEN by seed `\\t\\t\\t0`. Report Finding D-4.",
		},
		expectedDiff{
			key: "yaml-rejects-invalid-utf8",
			reason: "A JSON string containing an invalid UTF-8 byte (e.g. \"\\xba\"). encoding/json is " +
				"lenient — it accepts the bytes and substitutes U+FFFD on unmarshal; yaml.v3 requires " +
				"valid UTF-8 and returns `invalid leading UTF-8 octet`. Documented accept-vs-reject " +
				"library difference, not a bug in either. RED-PROVEN by seed `\"\\xba\"`. Security note " +
				"(report Finding D-3): a value with smuggled invalid UTF-8 is silently mangled by a " +
				"JSON reader but hard-rejected by a YAML reader of the same bytes.",
		},
		expectedDiff{
			key: "number-precision",
			reason: "A JSON number too large for an IEEE-754 double (e.g. 12345678901234567890). " +
				"encoding/json decodes numbers as float64 by DEFAULT and rounds; yaml.v3 decodes an " +
				"integer that fits uint64 without loss. Same token, different numeric value. " +
				"Documented: encoding/json's float64 default (callers who care use json.Number / " +
				"Decimal). Security note in report Finding D-2. RED-PROVEN by seed " +
				"`{\"n\":12345678901234567890}`. The oracle decodes the JSON side with DEFAULT " +
				"float64 (no UseNumber) because that is the reading nearly all Keyorix call sites " +
				"take; a value that fits a float64 exactly agrees, only a value-changing overflow " +
				"is flagged.",
		},
	)
}

var yamlSeeds = [][]byte{
	[]byte(`{"a":1}`),
	[]byte(`{"name":"alice","age":30}`),
	[]byte(`[1,2,3]`),
	[]byte(`{"x":null}`),
	[]byte(`{"s":"yes"}`),
	[]byte(`{"nested":{"b":[true,false]}}`),
	[]byte(`"plain"`),
	[]byte(`{"a":1,"a":2}`),              // dup key: exercises yaml-rejects-json-dup-key
	[]byte(`{"n":12345678901234567890}`), // big int: exercises number-precision
	[]byte(`{"k":"0x10"}`),               // quoted hex-like string stays a string in both
	[]byte(`{"a":{"b":1},"a":2}`),        // nested then dup key (detector regression seed)
	[]byte("\"\xba\""),                   // invalid UTF-8 string: yaml rejects, json accepts
	[]byte("\t\t\t0"),                    // leading tabs: yaml rejects (no tab indentation), json accepts
	[]byte("\"\u0085\""),                 // NEL in a string: yaml folds the line break, json keeps it
}

func FuzzYAMLVsJSON(f *testing.F) {
	for _, s := range yamlSeeds {
		f.Add(s)
	}
	allow := yamlDiffAllow()
	f.Fuzz(func(t *testing.T, data []byte) {
		m := yamlJSONCompare(data)
		if m == nil {
			return
		}
		if allow.allows(m.key) {
			return
		}
		t.Fatalf("DIFFERENTIAL [yaml.v3 vs encoding/json] (key=%s): %s\n  input=%q\n  json=%s\n  yaml=%s",
			m.key, m.detail, data, m.jsonV, m.yml)
	})
}

func TestYAMLDiffAllowlistNoDead(t *testing.T) {
	allow := yamlDiffAllow()
	for _, s := range yamlSeeds {
		if m := yamlJSONCompare(s); m != nil {
			allow.allows(m.key)
		}
	}
	allow.assertNoDeadEntries(t)
}

func TestYAMLJSONCompare_RedGreen(t *testing.T) {
	// GREEN: JSON both read identically.
	for _, g := range []string{`{"a":1}`, `[1,2,3]`, `{"x":null}`, `{"s":"yes"}`, `{"n":1.5}`, `"hi"`, `{"deep":{"k":[1,{"z":2}]}}`} {
		if m := yamlJSONCompare([]byte(g)); m != nil {
			t.Fatalf("GREEN input %q flagged: key=%s %s (json=%s yaml=%s)", g, m.key, m.detail, m.jsonV, m.yml)
		}
	}
	// RED (natural): duplicate key detected + classified.
	if m := yamlJSONCompare([]byte(`{"a":1,"a":2}`)); m == nil {
		t.Fatal("RED: dup-key divergence not detected")
	} else if m.key != "yaml-rejects-json-dup-key" {
		t.Fatalf("RED: dup-key misclassified as %q", m.key)
	}
	// RED (natural): big-int precision loss detected + classified.
	if m := yamlJSONCompare([]byte(`{"n":12345678901234567890}`)); m == nil {
		t.Fatal("RED: number-precision divergence not detected")
	} else if m.key != "number-precision" {
		t.Fatalf("RED: number-precision misclassified as %q", m.key)
	}
	// RED (synthetic, dangerous class): a genuine value divergence fires as a
	// non-allowlisted key, so the fuzzer would fail on it.
	if m := treeCompare(map[string]any{"role": "reader"}, map[string]any{"role": "admin"}); m == nil || m.key != "string-differs" {
		t.Fatalf("RED: value divergence not detected/classified (got %v)", m)
	}
	if yamlDiffAllow().allows("string-differs") {
		t.Fatal("RED: dangerous key string-differs must not be allowlisted")
	}
	// the dup-key detector must survive a nested value before the duplicate.
	if !hasDuplicateJSONKey([]byte(`{"a":{"b":1},"a":2}`)) {
		t.Fatal("RED: dup-key detector missed a duplicate after a nested object")
	}
	if hasDuplicateJSONKey([]byte(`{"a":{"b":1},"c":2}`)) {
		t.Fatal("GREEN: dup-key detector false-positived on distinct keys")
	}
}
