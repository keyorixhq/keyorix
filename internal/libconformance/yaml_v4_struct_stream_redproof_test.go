package libconformance

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	v3yaml "go.yaml.in/yaml/v3"
	v4yaml "go.yaml.in/yaml/v4"
)

// TestYAMLV4StructStreamRedGreen is the committed red/green proof for the three
// scope-gap oracles (S1 struct, S3 multi-doc, S2 round-trip). As with the
// single-doc proof, no production code is modified: every "defect" is fuzz INPUT
// or a forced verdict value.
func TestYAMLV4StructStreamRedGreen(t *testing.T) {
	// ========================= S1: struct-decode oracle =========================

	// structSplitVerdict pure-function red/green (the oracle's decision core).
	{
		// RED: a typed split where the any-path AGREED is a new typing-only
		// divergence → must fail.
		if fail, _ := structSplitVerdict("agree", true); !fail {
			t.Fatalf("RED failed: a typed split with any-path=agree must fail")
		}
		// RED: typed split where the any-path BOTH-REJECTED → new typing-only split.
		if fail, _ := structSplitVerdict("both-reject", true); !fail {
			t.Fatalf("RED failed: a typed split with any-path=both-reject must fail")
		}
		// RED: typed split tied to an UNTOLERATED any-path class → fail.
		if fail, _ := structSplitVerdict("value-mismatch", false); !fail {
			t.Fatalf("RED failed: a typed split tied to value-mismatch must fail")
		}
		// GREEN: typed split that is a downstream manifestation of a tolerated class.
		if fail, _ := structSplitVerdict("nonspecific-tag-nonempty-scalar", true); fail {
			t.Fatalf("GREEN failed: a typed split tied to a tolerated class must NOT fail")
		}
		// GREEN: any-path not comparable → no typed assertion.
		if fail, _ := structSplitVerdict("reencode-skip", true); fail {
			t.Fatalf("GREEN failed: reencode-skip must not fail")
		}
		t.Logf("S1 structSplitVerdict red/green proven")
	}

	// Real-bytes anchor: `int: ! 00` really splits the TYPED path (v3 accepts int
	// 0, v4 rejects — cannot construct the string "00" into an int field) while the
	// any-path diverges by the TOLERATED nonspecific-tag class, so the oracle
	// tolerates it. This is the concrete S1 signal the any-path oracle cannot see.
	{
		in := []byte("int: ! 00\n")
		type I struct {
			Int int `yaml:"int"`
		}
		var i3, i4 I
		e3 := v3yaml.Unmarshal(in, &i3)
		e4 := v4yaml.Unmarshal(in, &i4)
		if e3 != nil {
			t.Fatalf("precondition: v3 must ACCEPT `int: ! 00` into an int field (got %v)", e3)
		}
		if e4 == nil {
			t.Fatalf("precondition: v4 must REJECT `int: ! 00` into an int field (it keeps the raw string)")
		}
		if i3.Int != 0 {
			t.Fatalf("precondition: v3 must resolve `! 00` to int 0, got %d", i3.Int)
		}
		anyClass, anyTol := anyPathVerdict(in)
		if anyClass != "nonspecific-tag-nonempty-scalar" || !anyTol {
			t.Fatalf("precondition: the any-path for `int: ! 00` must be the tolerated nonspecific-tag class, got %q (tol=%v)", anyClass, anyTol)
		}
		if fail, _ := structSplitVerdict(anyClass, anyTol); fail {
			t.Fatalf("the real `int: ! 00` struct split must be TOLERATED (it is a downstream manifestation of %q)", anyClass)
		}
		t.Logf("S1 real anchor proven: `int: ! 00` splits the typed path (v3=int 0, v4 rejects), tolerated via any-path class %q", anyClass)
	}

	// GREEN: the SAME value into a STRING field does not split (both keep "00").
	{
		in := []byte("str: ! 00\n")
		type S struct {
			Str string `yaml:"str"`
		}
		var s3, s4 S
		if v3yaml.Unmarshal(in, &s3) != nil || v4yaml.Unmarshal(in, &s4) != nil {
			t.Fatalf("precondition: `str: ! 00` must be accepted into a string field by BOTH")
		}
		if s3.Str != "00" || s4.Str != "00" {
			t.Fatalf("GREEN failed: both must keep `! 00` as \"00\" in a string field, got v3=%q v4=%q", s3.Str, s4.Str)
		}
		t.Logf("S1 GREEN proven: `! 00` into a string field agrees (\"00\"); no typed split")
	}

	// Real config.Config exercise: a benign config fragment decodes identically.
	{
		in := []byte("environment: production\nserver:\n  http:\n    enabled: true\n")
		var c3, c4 config.Config
		if v3yaml.Unmarshal(in, &c3) != nil || v4yaml.Unmarshal(in, &c4) != nil {
			t.Fatalf("precondition: a benign config fragment must decode into config.Config in BOTH")
		}
		cb3, _ := v3yaml.Marshal(c3)
		cb4, _ := v3yaml.Marshal(c4)
		if !bytes.Equal(cb3, cb4) {
			t.Fatalf("GREEN failed: a benign config fragment decoded differently into config.Config across v3/v4")
		}
		t.Logf("S1 config.Config GREEN proven: benign fragment decodes identically")
	}

	// Strict-mode EOF handling: an empty document is a valid all-default config
	// under v3 KnownFields(true) (EOF treated as accept) — matches Config.Load.
	{
		var c3 config.Config
		dec := v3yaml.NewDecoder(bytes.NewReader([]byte("")))
		dec.KnownFields(true)
		if err := dec.Decode(&c3); err != io.EOF {
			t.Fatalf("precondition: empty doc under KnownFields must return io.EOF, got %v", err)
		}
		t.Logf("S1 strict-mode EOF handling proven (empty doc = all-default config)")
	}

	// Strict-mode empty-document divergence (class v4-strict-rejects:empty-doc):
	// v3's strict Decoder treats an empty stream as EOF → all-default config
	// (matching Config.Load); v4's one-shot strict Load REJECTS it ("no documents
	// in stream"). A real, documented migration gotcha of v4's strict Load API.
	{
		var c3, c4 config.Config
		dec := v3yaml.NewDecoder(bytes.NewReader([]byte("")))
		dec.KnownFields(true)
		e3 := dec.Decode(&c3)
		if e3 == io.EOF {
			e3 = nil
		}
		e4 := v4yaml.Load([]byte(""), &c4, v4yaml.WithKnownFields())
		if e3 != nil {
			t.Fatalf("precondition: v3 strict must ACCEPT empty (EOF→nil), got %v", e3)
		}
		if e4 == nil {
			t.Fatalf("precondition: v4 strict Load must REJECT empty")
		}
		if !isV4StrictEmptyDocSplit(e3, e4) {
			t.Fatalf("the empty-doc strict split must be recognised (class v4-strict-rejects:empty-doc); got e4=%v", e4)
		}
		// RED: a REAL unknown-field strict split must NOT be absorbed by this class.
		unknownErr := &yamlErr{"yaml: construct errors: line 1: field nope not found in type config.Config"}
		if isV4StrictEmptyDocSplit(nil, unknownErr) {
			t.Fatalf("an unknown-field strict rejection must NOT be absorbed by the empty-doc class")
		}
		t.Logf("S1 strict empty-doc divergence proven: v3 accepts empty (EOF), v4 strict Load rejects; unknown-field split not absorbed")
	}

	// ========================= S3: multi-doc oracle =========================

	// GREEN: a 2-document stream decodes to the same 2 documents in both libraries.
	{
		in := []byte("---\na: 1\n---\nb: 2\n")
		d3, e3 := decodeStreamV3(in)
		d4, e4 := decodeStreamV4(in)
		if e3 != nil || e4 != nil {
			t.Fatalf("precondition: the 2-doc stream must decode without error (v3=%v v4=%v)", e3, e4)
		}
		if len(d3) != 2 || len(d4) != 2 {
			t.Fatalf("GREEN failed: both must yield 2 documents, got v3=%d v4=%d", len(d3), len(d4))
		}
		for i := range d3 {
			cb3, _ := v3yaml.Marshal(d3[i])
			cb4, _ := v3yaml.Marshal(d4[i])
			if !bytes.Equal(cb3, cb4) {
				t.Fatalf("GREEN failed: document %d differs across v3/v4 (%q vs %q)", i, cb3, cb4)
			}
		}
		t.Logf("S3 GREEN proven: 2-doc stream decodes identically in both")
	}

	// The document-count-mismatch class is NOT in the table, so a count split is a
	// finding (RED direction). Prove the gate: the class must be absent.
	{
		if yamlV4ExpectedDiff["multidoc:count-mismatch"] {
			t.Fatalf("RED gate broken: multidoc:count-mismatch must NOT be tolerated")
		}
		t.Logf("S3 count-mismatch gate proven: a differing document count fails the target")
	}

	// Per-document nonspecific-tag divergence survives and is tolerated per-doc.
	{
		in := []byte("---\n! 00\n---\n! true\n")
		d3, e3 := decodeStreamV3(in)
		d4, e4 := decodeStreamV4(in)
		if e3 != nil || e4 != nil || len(d3) != 2 || len(d4) != 2 {
			t.Fatalf("precondition: the `!`-tag 2-doc stream must decode to 2 docs each (v3 err=%v n=%d, v4 err=%v n=%d)", e3, len(d3), e4, len(d4))
		}
		for i := range d3 {
			class := classifyYAMLV4ValueSplit(in, d3[i], d4[i])
			if class != "nonspecific-tag-nonempty-scalar" {
				t.Fatalf("doc %d: expected per-doc nonspecific-tag class, got %q (v3=%#v v4=%#v)", i, class, d3[i], d4[i])
			}
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("doc %d class %q must be tolerated", i, class)
			}
		}
		t.Logf("S3 per-doc divergence proven: each doc's `!`-tag split classes as the tolerated nonspecific-tag class")
	}

	// ========================= S2: round-trip oracle =========================

	// GREEN: a simple document is a round-trip fixed point in both libraries.
	{
		for _, lib := range []struct {
			name      string
			unmarshal func([]byte, any) error
			marshal   func(any) ([]byte, error)
		}{
			{"v3", v3yaml.Unmarshal, v3yaml.Marshal},
			{"v4", v4yaml.Unmarshal, v4yaml.Marshal},
		} {
			for _, in := range []string{"x: 1\n", "n: .nan\n", "- 1\n- 2\n", "! 00\n"} {
				var v1 any
				if lib.unmarshal([]byte(in), &v1) != nil {
					continue
				}
				enc, err := lib.marshal(v1)
				if err != nil {
					t.Fatalf("GREEN failed [%s]: Marshal of decoded %q failed: %v", lib.name, in, err)
				}
				var v2 any
				if err := lib.unmarshal(enc, &v2); err != nil {
					t.Fatalf("GREEN failed [%s]: re-decode of %q (encoded %q) failed: %v", lib.name, in, enc, err)
				}
				c1, _ := v3yaml.Marshal(v1)
				c2, _ := v3yaml.Marshal(v2)
				if !bytes.Equal(c1, c2) {
					t.Fatalf("GREEN failed [%s]: %q not idempotent (%q vs %q)", lib.name, in, c1, c2)
				}
			}
		}
		t.Logf("S2 GREEN proven: x:1 / .nan / seq / `! 00` are round-trip fixed points in both libraries")
	}

	// RED: a genuinely non-idempotent round-trip (two distinct canonical values)
	// classifies as value-mismatch, which is NOT tolerated → the oracle fires.
	{
		v1 := map[string]any{"k": 1}
		v2 := map[string]any{"k": 2}
		c1, _ := v3yaml.Marshal(v1)
		c2, _ := v3yaml.Marshal(v2)
		if reflect.DeepEqual(c1, c2) {
			t.Fatalf("RED precondition: the two forced values must canonicalise differently")
		}
		class := classifyYAMLV4ValueSplit([]byte("k: 1"), v1, v2)
		if yamlV4ExpectedDiff[class] || yamlV4RoundTripExpectedDiff[class] {
			t.Fatalf("RED failed: a genuine value drift (%q) must NOT be tolerated by either table", class)
		}
		t.Logf("S2 RED proven: a non-idempotent drift classes as %q and fires the oracle", class)
	}
}
