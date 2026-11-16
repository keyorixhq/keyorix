package libconformance

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	v3yaml "go.yaml.in/yaml/v3"
	v4yaml "go.yaml.in/yaml/v4"
)

// This file adds three oracles that close the scope gaps the DF2 `any`-path
// differential (FuzzYAMLV4Differential) explicitly did NOT cover
// (EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md §"What this oracle does NOT
// verify", items S1/S2/S3):
//
//   - FuzzYAMLV4StructDifferential (S1) — decode the SAME bytes into a TYPED Go
//     struct (the real internal/config.Config family the server loads at runtime,
//     plus a synthetic struct), with v3 AND v4, PLUS v4 WithKnownFields strict
//     mode vs v3 KnownFields(true). The `any`-path can agree while the typed path
//     diverges (e.g. `int: ! 00` → v3 resolves int 0, v4 keeps string "00" and
//     then CANNOT construct it into an int field, so v4 rejects where v3 accepts).
//
//   - FuzzYAMLV4MultiDocDifferential (S3) — decode EVERY document of a `---`
//     stream (not just the first, which is all Unmarshal reads) with v3's Decoder
//     loop and v4's Loader loop, and compare the document SEQUENCE.
//
//   - FuzzYAMLV4RoundTrip (S2) — within EACH library, decode→encode→decode and
//     assert idempotence (the re-decode of a library's own Marshal output
//     canonicalises to the first decode). A non-idempotent round-trip is a genuine
//     library footgun, invisible to a one-shot decode differential.
//
// All three reuse the single-doc classifier vocabulary (classifyYAMLV4Split /
// classifyYAMLV4ValueSplit / yamlV4ExpectedDiff). The tie that makes the struct
// and multi-doc oracles sound without inventing a parallel tolerance table: a
// typed-struct or per-document divergence is a FINDING unless the `any`-path for
// the same bytes ALSO diverges by an already-tolerated class — i.e. the typed
// divergence must be a downstream manifestation of a known library-level one. A
// struct/stream split where the `any`-path AGREED is new and fails.

// synthYAMLDoc is the synthetic struct used alongside the real config.Config. It
// spans the scalar kinds and container shapes most likely to expose a typed-decode
// divergence: a strict int/bool/float field (where v4's string-keeping `!` rule
// causes a construct error v3 does not), an `any` field (where a value divergence
// survives into the struct), and nested containers.
type synthYAMLDoc struct {
	Str   string            `yaml:"str"`
	Int   int               `yaml:"int"`
	Bool  bool              `yaml:"bool"`
	Float float64           `yaml:"float"`
	List  []int             `yaml:"list"`
	Map   map[string]string `yaml:"map"`
	Any   any               `yaml:"any"`
	Sub   struct {
		Name string `yaml:"name"`
		N    int    `yaml:"n"`
	} `yaml:"sub"`
}

// anyPathVerdict decodes data on the `any` path with both libraries and reduces
// the result to (class, tolerated). It is the reference the typed/stream oracles
// tie their own divergences back to. Classes:
//   - "agree"        — both accept and canonicalise equal (no library divergence)
//   - "both-reject"  — both reject (no divergence to explain)
//   - "reencode-skip"— one re-encode failed; not comparable, treated as no-signal
//   - otherwise the classifyYAMLV4* class string, with tolerated = yamlV4ExpectedDiff[class]
func anyPathVerdict(data []byte) (class string, tolerated bool) {
	var v3v, v4v any
	e3 := v3yaml.Unmarshal(data, &v3v)
	e4 := v4yaml.Unmarshal(data, &v4v)
	a3, a4 := e3 == nil, e4 == nil
	if a3 != a4 {
		c := classifyYAMLV4Split(e3, e4)
		return c, yamlV4ExpectedDiff[c]
	}
	if !a3 {
		return "both-reject", true
	}
	cb3, m3 := v3yaml.Marshal(v3v)
	cb4, m4 := v3yaml.Marshal(v4v)
	if m3 != nil || m4 != nil {
		return "reencode-skip", true
	}
	if bytes.Equal(cb3, cb4) {
		return "agree", true
	}
	c := classifyYAMLV4ValueSplit(data, v3v, v4v)
	return c, yamlV4ExpectedDiff[c]
}

// structSplitVerdict is the pure decision the struct and multi-doc oracles apply
// to a typed/stream divergence, given how the `any`-path for the same bytes
// behaved. Factored out so its red/green can be proven directly.
//
//   - A typed/stream divergence where the `any`-path AGREED (or both rejected) is
//     NEW — the typing/streaming introduced a split the libraries do not have at
//     the value level. That is a finding (fail=true).
//   - A typed/stream divergence tied to a TOLERATED `any`-path class is a known
//     downstream manifestation (fail=false).
//   - A typed/stream divergence tied to an UNTOLERATED `any`-path class fails (the
//     `any`-path oracle would fail on it too).
func structSplitVerdict(anyClass string, anyTolerated bool) (fail bool, reason string) {
	switch anyClass {
	case "agree":
		return true, "typed/stream path diverged where the any-path AGREED (new typing/streaming-only divergence)"
	case "both-reject":
		return true, "typed/stream path diverged where the any-path BOTH-REJECTED (new typing/streaming-only divergence)"
	case "reencode-skip":
		return false, "any-path not comparable (re-encode skipped); no typed/stream assertion"
	}
	if anyTolerated {
		return false, "typed/stream divergence is a downstream manifestation of tolerated any-path class " + anyClass
	}
	return true, "typed/stream divergence tied to UNTOLERATED any-path class " + anyClass
}

// FuzzYAMLV4StructDifferential — S1. See the file header.
func FuzzYAMLV4StructDifferential(f *testing.F) {
	seeds := []string{
		"",
		"str: hello\nint: 5\nbool: true\nfloat: 1.5\n",
		"int: ! 00\n",       // v3 int 0 / v4 construct-error into int field
		"int: ! 123\n",      // same, non-trivial
		"str: ! 00\n",       // into a STRING field both accept "00" (no struct split)
		"any: ! 00\n",       // value split survives into an `any` field
		"any: !\n",          // empty `!` into `any` (D1) survives
		"bool: ! true\n",    // v3 bool / v4 construct-error into bool field
		"float: ! 1.5\n",    // v3 float / v4 construct-error into float field
		"list: [1, 2, 3]\n", // sequence into []int
		"map: {a: x, b: y}\n",
		"sub:\n  name: n\n  n: 7\n",
		"environment: production\n",            // real config field
		"server:\n  http:\n    enabled: true\n", // nested real config
		"unknown_top_level_key: 1\n",            // strict-mode unknown-field probe
		"storage:\n  type: sqlite\n",
		"minimum_cli_version: ! 1.2.0\n", // `!` on a real string field
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		anyClass, anyTol := anyPathVerdict(data)

		checkStructDecode[synthYAMLDoc](t, data, "synth", anyClass, anyTol)
		checkStructDecode[config.Config](t, data, "config.Config", anyClass, anyTol)

		// Strict-mode parity: the real server loads config with KnownFields(true),
		// so compare v3 KnownFields(true) against v4 WithKnownFields() — a split
		// there (one rejects an unknown field, the other accepts) is a migration
		// hazard for the config loader specifically.
		checkStrictDecode(t, data, anyClass, anyTol)
	})
}

// checkStructDecode decodes data into T with v3 and v4 (lenient Unmarshal) and
// applies the structSplitVerdict tie-in.
func checkStructDecode[T any](t *testing.T, data []byte, label, anyClass string, anyTol bool) {
	t.Helper()
	var s3, s4 T
	e3 := v3yaml.Unmarshal(data, &s3)
	e4 := v4yaml.Unmarshal(data, &s4)
	a3, a4 := e3 == nil, e4 == nil

	if a3 != a4 {
		// Typed-specific tolerances first (a split the any-path cannot explain
		// because it lives purely in field-type construction).
		if yamlV4StructExpectedDiff[classifyTypedSplit(e3, e4)] {
			return
		}
		if fail, reason := structSplitVerdict(anyClass, anyTol); fail {
			t.Fatalf("struct accept/reject split [%s]: %s\n  input=%q\n  v3 accept=%v err=%v\n  v4 accept=%v err=%v\n  any-path class=%q tolerated=%v  typed-class=%q",
				label, reason, data, a3, e3, a4, e4, anyClass, anyTol, classifyTypedSplit(e3, e4))
		}
		return
	}
	if !a3 {
		return // both rejected
	}
	// Both accept — compare decoded struct values via one canonical encoder.
	cb3, m3 := v3yaml.Marshal(s3)
	cb4, m4 := v3yaml.Marshal(s4)
	if m3 != nil || m4 != nil {
		return // not comparable
	}
	if bytes.Equal(cb3, cb4) {
		return
	}
	if fail, reason := structSplitVerdict(anyClass, anyTol); fail {
		t.Fatalf("struct value split [%s]: %s\n  input=%q\n  v3 canonical=%q\n  v4 canonical=%q\n  any-path class=%q tolerated=%v",
			label, reason, data, cb3, cb4, anyClass, anyTol)
	}
}

// checkStrictDecode compares v3's KnownFields(true) decoder against v4's
// WithKnownFields() load for accept/reject parity into config.Config (the real
// strict load path). Unknown-field rejection should agree; a split is tied back
// to the any-path verdict exactly like checkStructDecode.
func checkStrictDecode(t *testing.T, data []byte, anyClass string, anyTol bool) {
	t.Helper()
	var c3, c4 config.Config
	dec := v3yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	e3 := dec.Decode(&c3)
	if e3 == io.EOF {
		e3 = nil // empty document is a valid (all-default) config, as Config.Load treats it
	}
	e4 := v4yaml.Load(data, &c4, v4yaml.WithKnownFields())
	a3, a4 := e3 == nil, e4 == nil
	if a3 == a4 {
		return // agree on accept/reject (strict mode value equality is covered by the lenient struct check)
	}
	// Known typed/strict-API divergences first (empty-doc, non-integral float into
	// an int field) — scoped tightly by classifyTypedSplit so a real unknown-field
	// split is never absorbed.
	if yamlV4StructExpectedDiff[classifyTypedSplit(e3, e4)] {
		return
	}
	// An unknown-field rejection on one side only is a strict-mode-specific split;
	// it is NOT explained by the any-path (which ignores unknown fields). Tie it to
	// the any-path only when the any-path itself split; otherwise it is a genuine
	// strict-mode divergence worth surfacing.
	if fail, reason := structSplitVerdict(anyClass, anyTol); fail {
		// Distinguish the unknown-field case: if BOTH any-decode fine but strict
		// splits, it is an unknown-field-handling divergence between the two strict
		// modes — a real migration finding for the config loader.
		t.Fatalf("strict-mode (KnownFields) accept/reject split [config.Config]: %s\n  input=%q\n  v3(KnownFields) accept=%v err=%v\n  v4(WithKnownFields) accept=%v err=%v\n  any-path class=%q tolerated=%v",
			reason, data, a3, e3, a4, e4, anyClass, anyTol)
	}
}

// yamlV4StructExpectedDiff lists tolerated TYPED-decode divergence classes that
// live purely in field-type construction (invisible to the any-path). EMPTY of
// field-strictness divergences on purpose — the two entries are v4-strict/typed
// construction gotchas found by the DF3 struct fuzzer, each red/green proven and
// documented in EXPECTED-DIFFERENCES (D13, D14). A class not here (classifyTyped
// Split → "typed:other") falls through to the any-path tie-in and is a finding.
var yamlV4StructExpectedDiff = map[string]bool{
	// v4's one-shot strict Load rejects a document-less stream ("no documents in
	// stream") where v3's strict Decoder returns io.EOF, which Config.Load treats
	// as a valid all-default config. A migration gotcha of v4's strict Load API.
	"v4-strict-rejects:empty-doc": true,

	// A NON-INTEGRAL float value decoded into an INTEGER struct field (e.g.
	// `int: 0.1`). v3 silently COERCES it, truncating 0.1 -> int 0 (DATA LOSS);
	// v4 REJECTS ("cannot construct !!float `0.1` into int"). Integral floats
	// (5.0, 1e3) are accepted by BOTH, so only a non-integral float splits. v3 is
	// the reachable, LENIENT, data-losing side (same footgun family as the D8
	// block-scalar / D4 truncation silent drops); v4 is strict. Not a Keyorix
	// defect (v4 has no live caller), and a config int field receiving a fractional
	// float is exotic -- but a genuine v3 silent-data-loss footgun worth noting.
	"v4-strict-rejects:nonintegral-float-into-int": true,
}

// classifyTypedSplit names a typed-decode accept/reject split (exactly one of
// e3/e4 is non-nil). It keys on the rejecting side and a coarse reason so a
// tolerated class is recognised without matching volatile line/column text. A
// shape it does not recognise returns "typed:other", which is NOT tolerated.
func classifyTypedSplit(e3, e4 error) string {
	msg, rejecter := "", ""
	switch {
	case e3 != nil && e4 == nil:
		msg, rejecter = strings.ToLower(e3.Error()), "v3"
	case e4 != nil && e3 == nil:
		msg, rejecter = strings.ToLower(e4.Error()), "v4"
	default:
		return "typed:none" // not a split
	}
	switch {
	case rejecter == "v4" && strings.Contains(msg, "no documents in stream"):
		return "v4-strict-rejects:empty-doc"
	case rejecter == "v4" && strings.Contains(msg, "float") && strings.Contains(msg, "into int"):
		return "v4-strict-rejects:nonintegral-float-into-int"
	default:
		return "typed:other"
	}
}

// FuzzYAMLV4MultiDocDifferential — S3. Decode EVERY document of a stream.
func FuzzYAMLV4MultiDocDifferential(f *testing.F) {
	seeds := []string{
		"a: 1\n",
		"---\na: 1\n---\nb: 2\n",
		"---\na: 1\n---\nb: 2\n---\nc: 3\n",
		"a: 1\n---\nb: 2\n",
		"---\n---\n",       // two empty documents
		"---\n! 00\n---\n! true\n", // per-doc nonspecific-tag divergence in docs 1 and 2
		"{}\n---\n[]\n",
		"\n---\n\n",
		"--- a\n--- b\n",
		"0\n---\n: ",         // doc2 is the D2 empty-implicit-key: v3 stream errors, v4 accepts
		"a: 1\n---\n! 00\n", // doc2 is a D12 nonspecific-tag value divergence
		">\n0",              // folded block scalar under-indented: v3 stream rejects / v4 accepts
		"&0?",               // anchor then ?: v3 rejects mapping-key-context / v4 accepts
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		docs3, err3 := decodeStreamV3(data)
		docs4, err4 := decodeStreamV4(data)

		// Stream-level accept/reject parity. The split can be driven by ANY document
		// of the stream (e.g. "0\n---\n: " where doc 1 agrees but doc 2 is the D2
		// empty-implicit-key that v3 rejects and v4 accepts), so it must be classified
		// from the STREAM error directly with the accept/reject vocabulary — NOT tied
		// to the first-document any-path verdict, which only sees doc 1.
		a3, a4 := err3 == nil, err4 == nil
		if a3 != a4 {
			class := classifyYAMLV4Split(err3, err4)
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("multi-doc stream accept/reject split [class=%q]\n  input=%q\n  v3 docs=%d err=%v\n  v4 docs=%d err=%v",
					class, data, len(docs3), err3, len(docs4), err4)
			}
			return
		}
		if !a3 {
			return // both streams errored
		}
		// Document-count parity: a different split of the stream into documents is a
		// structural divergence of its own (class multidoc:count-mismatch, absent
		// from the table → a finding until triaged).
		if len(docs3) != len(docs4) {
			if !yamlV4ExpectedDiff["multidoc:count-mismatch"] {
				t.Fatalf("multi-doc stream document-COUNT split [class=%q]\n  input=%q\n  v3 docs=%d\n  v4 docs=%d",
					"multidoc:count-mismatch", data, len(docs3), len(docs4))
			}
			return
		}
		// Per-document value parity, reusing the single-doc value classifier.
		for i := range docs3 {
			cb3, m3 := v3yaml.Marshal(docs3[i])
			cb4, m4 := v3yaml.Marshal(docs4[i])
			if m3 != nil || m4 != nil {
				continue
			}
			if bytes.Equal(cb3, cb4) {
				continue
			}
			class := classifyYAMLV4ValueSplit(data, docs3[i], docs4[i])
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("multi-doc per-document value split [doc %d, class=%q]\n  input=%q\n  v3 canonical=%q\n  v4 canonical=%q",
					i, class, data, cb3, cb4)
			}
		}
	})
}

func decodeStreamV3(data []byte) ([]any, error) {
	dec := v3yaml.NewDecoder(bytes.NewReader(data))
	var docs []any
	for {
		var d any
		err := dec.Decode(&d)
		if err == io.EOF {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		docs = append(docs, d)
	}
}

func decodeStreamV4(data []byte) ([]any, error) {
	loader, err := v4yaml.NewLoader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var docs []any
	for {
		var d any
		err := loader.Load(&d)
		if err == io.EOF {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		docs = append(docs, d)
	}
}

// FuzzYAMLV4RoundTrip — S2. Per-library decode→encode→decode idempotence.
func FuzzYAMLV4RoundTrip(f *testing.F) {
	seeds := []string{
		"x: 1\n", "a:\n  b: 2\n", "- 1\n- 2\n", "n: .nan\n", "i: .inf\n",
		"s: 'hello world'\n", "t: true\n", "f: 3.14\n", "! 00\n", "!\n",
		"anchor: &a 1\nref: *a\n", "key: |\n  multi\n  line\n",
		"m: {a: 1, b: 2}\n", "e: 1_000\n", "neg: -0\n", "ts: 2020-01-02\n",
		"-.000\n", "v: -0.0\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		roundTripOne(t, data, "v3", v3yaml.Unmarshal, v3yaml.Marshal)
		roundTripOne(t, data, "v4", v4yaml.Unmarshal, v4yaml.Marshal)
	})
}

// roundTripOne asserts that for one library, decoding its OWN Marshal output
// reproduces the same canonical value as the first decode (idempotence). The
// canonical comparator is v3.Marshal applied to both decoded values, so NaN and
// map-ordering are stable (identical to the single-doc oracle).
func roundTripOne(t *testing.T, data []byte, label string,
	unmarshal func([]byte, any) error, marshal func(any) ([]byte, error)) {
	t.Helper()
	var v1 any
	if unmarshal(data, &v1) != nil {
		return // input not accepted by this library; nothing to round-trip
	}
	enc, err := marshal(v1)
	if err != nil {
		// A library that decodes a value but cannot re-encode it is itself a
		// finding (the resguard oracle aside, a decode→encode asymmetry is a footgun).
		t.Fatalf("round-trip [%s]: decoded but Marshal failed\n  input=%q\n  value=%#v\n  err=%v", label, data, v1, err)
	}
	var v2 any
	if err := unmarshal(enc, &v2); err != nil {
		t.Fatalf("round-trip [%s]: re-decode of own Marshal output FAILED\n  input=%q\n  encoded=%q\n  err=%v", label, data, enc, err)
	}
	// Canonicalise both with v3.Marshal (the fixed comparator) and compare.
	c1, m1 := v3yaml.Marshal(v1)
	c2, m2 := v3yaml.Marshal(v2)
	if m1 != nil || m2 != nil {
		return
	}
	if bytes.Equal(c1, c2) {
		return
	}
	// A non-idempotent round-trip. Try the round-trip-specific classifier first,
	// then the single-doc value classifier; a tolerated class is excused, anything
	// else is a finding.
	if !reflect.DeepEqual(c1, c2) {
		rtClass := classifyRoundTripDrift(v1, v2)
		if yamlV4RoundTripExpectedDiff[rtClass] {
			return
		}
		class := classifyYAMLV4ValueSplit(enc, v1, v2)
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("round-trip [%s] NOT idempotent [rt-class=%q value-class=%q]\n  input=%q\n  first decode canonical=%q\n  re-decode canonical=%q",
				label, rtClass, class, data, c1, c2)
		}
	}
}

// classifyRoundTripDrift names a per-library decode→encode→decode non-idempotence.
// v1 is the first decode, v2 the re-decode of v1's own Marshal output.
func classifyRoundTripDrift(v1, v2 any) string {
	// Negative-zero float round-trips to int 0 (v3): a float -0.0 Marshals to "-0",
	// which v3 re-reads as the int 0 (the D10 negative-zero rule) — so the type and
	// canonical change (-0.0 float -> 0 int). The round-trip manifestation of D10;
	// recognised by the same negZeroIntVsFloatOnly shape with v2(int)/v1(float).
	if n, ok := negZeroIntVsFloatOnly(v2, v1); ok && n > 0 {
		return "roundtrip:negzero-float-to-int"
	}
	return "roundtrip:other"
}

// yamlV4RoundTripExpectedDiff lists round-trip-specific non-idempotence classes
// (distinct from the cross-library yamlV4ExpectedDiff). The one entry is the D10
// negative-zero footgun biting across a round-trip (v3 only); any other class is a
// finding until triaged and justified here.
var yamlV4RoundTripExpectedDiff = map[string]bool{
	"roundtrip:negzero-float-to-int": true,
}
