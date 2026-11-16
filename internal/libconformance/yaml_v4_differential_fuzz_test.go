package libconformance

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	v3yaml "go.yaml.in/yaml/v3"
	v4yaml "go.yaml.in/yaml/v4"
)

// FuzzYAMLV4Differential is a differential fuzz target over the v3→v4 MAJOR
// version jump of the go.yaml.in YAML implementation this module links:
//
//   - go.yaml.in/yaml/v3 v3.0.5 — the ecosystem's canonical home for the same
//     library Keyorix tooling imports (scripts/e2e, scripts/metrics/*,
//     scripts/fuzzing/configspace, scripts/ci/guardinputs — the live callers
//     traced in FuzzYAMLSiblingDifferential). This side IS reachable.
//   - go.yaml.in/yaml/v4 v4.0.0 — the major-version REWRITE the ecosystem is
//     migrating to, already in this module's graph. It has NO live Keyorix caller
//     today, so it is a forward-looking migration-risk oracle: a v4-only
//     divergence is a break that materialises only if Keyorix bumps to v4.
//
// This is distinct from FuzzYAMLSiblingDifferential, which compares two PATCH
// releases of v3 (v3.0.1 vs v3.0.5). A major rewrite is exactly where accept/
// reject verdicts or decoded values can silently diverge, so "do v3 and v4 still
// agree, byte-for-byte, on accept/reject and decoded value, and does neither do
// unbounded work?" is the real question here.
//
// Three oracles. None is panic-only — a panic in either library also surfaces
// natively and is itself a finding.
//
//  1. BOUNDED WORK (resguard). Each Unmarshal is metered independently and
//     checked against a calibrated budget (testdata/resguard-yaml-v4.json). A
//     YAML decoder's alias expansion and deep nesting are a classic DoS surface
//     (the "billion laughs" shape); both libraries cap it today, so the oracle
//     fails only if EITHER library's alloc/mallocs/live-heap for a bounded input
//     exceeds the super-linear ceiling — i.e. one of them regressed its cap, or
//     the two caps diverge enough that one amplifies where the other does not.
//     Meters enabled (FATAL): alloc_bytes and mallocs — the ReadMemStats DELTAS
//     around the single Unmarshal, the only resources a pure in-memory parse can
//     blow that are attributable to ONE input. They are judged by an ABSOLUTE
//     ceiling (ModeAbsolute) because a YAML parse's large fixed per-call overhead
//     inflates the per-byte slope so far it never fires. wall/cpu are advisory
//     (process-wide, noisy on a shared host — never fatal). live_heap is
//     deliberately NOT fatal: it is the whole-process post-GC heap, not a
//     per-input delta, so it reflects unrelated test-binary heap and false-fires.
//     NOT enabled: disk/net/sleep/log/DB (an in-memory Unmarshal touches none).
//
//  2. ACCEPT/REJECT PARITY. For the same bytes both libraries must agree on
//     accept (nil error) vs reject. A split verdict fails unless its normalized
//     class is in the committed EXPECTED-DIFFERENCE table (yamlV4ExpectedDiff /
//     EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md).
//
//  3. DECODED-VALUE EQUALITY. When BOTH accept, the two decoded values must be
//     equal. Equality is checked by re-marshalling each decoded value with ONE
//     fixed encoder (v3's Marshal) and comparing bytes — order-independent
//     (Marshal sorts map keys), NaN-stable (both re-encode to `.nan`, so
//     reflect.DeepEqual's NaN!=NaN trap is avoided) and immune to int/float
//     formatting nuances. A mismatch is gated by the same table ("value-mismatch").
func FuzzYAMLV4Differential(f *testing.F) {
	seeds := []string{
		"",
		"null",
		"x: 1",
		"x: 1\ny: 2\n",
		"x: 1\nx: 2\n",              // duplicate key (both expected to reject)
		"- 1\n- 2\n- 3\n",           // sequence
		"a:\n  b:\n    c: 1\n",      // nested maps
		"foo: !!str 123\n",          // explicit tag
		"n: .nan\ni: .inf\n",        // float specials (NaN re-encode parity)
		"big: 0x7fffffffffffffff\n", // hex int
		"t: true\nf: no\ny: yes\n",  // yaml 1.1 vs 1.2 bools
		"o: 0o17\n",                 // octal 1.2
		"o: 017\n",                  // octal leading-zero
		"v: 0b101\n",                // binary
		"e: 1_000\n",                // underscore digits
		"s: 2020-01-02\n",           // timestamp
		"anchor: &a 1\nref: *a\n",   // anchor/alias
		"merge: &m {a: 1}\nd: {<<: *m, b: 2}\n", // merge key
		"key: |\n  multi\n  line\n", // block scalar
		"? [a, b]\n: val\n",         // complex mapping key (both reject)
		"!",                         // non-specific tag on empty scalar (v3 null / v4 "")
		"a: !\nb: !!str\n",          // mixed: ! diverges, !!str agrees
		":",                         // empty implicit key (v3 rejects / v4 null key)
		"- :\n",                     // empty implicit key inside a sequence
		"::",                        // NOT a split: both accept (key "::")
		"0: !",                      // ! on empty scalar under an INT key (map[any]any)
		"\x7f",                      // DEL control char (v3 rejects / v4 accepts)
		"k: a\x80b\n",               // C1 control embedded in a scalar value
		"0\n:",                      // scalar then ':' next line (v3 accepts+truncates / v4 rejects)
		"'': empty-key\n",           // empty key
		"a: 1\nb: {c: 2, c: 3}\n",   // nested duplicate key
		"---\na: 1\n---\nb: 2\n",    // multi-document (single-value decode)
		"key: =\n",                  // the '=' value
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	budget := loadYAMLV4Budget(f)
	probe := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound the input. Both libraries cap alias expansion and nesting, and we
		// are testing parity + bounded work, not re-testing their internal caps on
		// megabyte inputs; keep inputs modest so a slow pathological expansion in
		// ONE library does not masquerade as a disagreement with the other, and so
		// the budget's super-linear model stays meaningful.
		if len(data) > 8192 {
			return
		}

		var v3val, v4val any
		var err3, err4 error
		// Oracle 1: bounded work. Measure each decode independently so a hit names
		// the offending library. Check fails the input on a super-linear blowup.
		c3 := probe.Measure(len(data), func() { err3 = v3yaml.Unmarshal(data, &v3val) })
		budget.Check(func(format string, args ...any) {
			t.Fatalf("v3 bounded-work budget exceeded\n  input=%q (%d bytes)\n  "+format, append([]any{data, len(data)}, args...)...)
		}, c3)

		c4 := probe.Measure(len(data), func() { err4 = v4yaml.Unmarshal(data, &v4val) })
		budget.Check(func(format string, args ...any) {
			t.Fatalf("v4 bounded-work budget exceeded\n  input=%q (%d bytes)\n  "+format, append([]any{data, len(data)}, args...)...)
		}, c4)

		accept3, accept4 := err3 == nil, err4 == nil

		// Oracle 2: accept/reject parity.
		if accept3 != accept4 {
			class := classifyYAMLV4Split(err3, err4)
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("accept/reject disagreement [class=%q]\n  input=%q\n  v3 accept=%v err=%v\n  v4 accept=%v err=%v",
					class, data, accept3, err3, accept4, err4)
			}
			return // a listed split: v3 and v4 legitimately diverge here.
		}
		if !accept3 {
			return // both rejected — nothing more to compare.
		}

		// Oracle 3: decoded-value equality via one fixed canonical encoder (v3).
		canon3, mErr3 := v3yaml.Marshal(v3val)
		canon4, mErr4 := v3yaml.Marshal(v4val)
		if mErr3 != nil || mErr4 != nil {
			if (mErr3 == nil) != (mErr4 == nil) {
				t.Fatalf("re-encode disagreement\n  input=%q\n  v3Err=%v v4Err=%v", data, mErr3, mErr4)
			}
			return
		}
		if !reflect.DeepEqual(canon3, canon4) {
			class := classifyYAMLV4ValueSplit(v3val, v4val)
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("decoded-value disagreement [class=%q]\n  input=%q\n  v3 canonical=%q\n  v4 canonical=%q",
					class, data, canon3, canon4)
			}
		}
	})
}

// classifyYAMLV4Split maps a split accept/reject verdict to a stable, coarse
// class string so the EXPECTED-DIFFERENCE table can enumerate known divergences
// by name rather than by exact error text (which carries line/column noise, and
// which v4 re-worded relative to v3 — e.g. v4 says "construct errors" where v3
// says "unmarshal errors", and v4 prefixes a "line N:" where v3 sometimes does
// not; classification is deliberately on the SIDE that rejects plus a coarse
// reason, not on the literal string).
func classifyYAMLV4Split(err3, err4 error) string {
	// Exactly one is non-nil here (callers guarantee a split).
	msg, side := "", ""
	if err3 != nil {
		msg, side = err3.Error(), "v3-rejects"
	} else {
		msg, side = err4.Error(), "v4-rejects"
	}
	msg = strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "already defined"):
		return side + ":duplicate-key"
	case strings.Contains(msg, "excessive aliasing") || strings.Contains(msg, "alias") || strings.Contains(msg, "anchor"):
		return side + ":alias"
	case strings.Contains(msg, "unmarshal errors") || strings.Contains(msg, "construct errors") || strings.Contains(msg, "cannot unmarshal"):
		return side + ":type"
	case strings.Contains(msg, "map key"):
		return side + ":complex-key"
	case strings.Contains(msg, "expected <document start>"):
		// A plain scalar on one line followed by a value indicator `:` at the start
		// of the next line (e.g. "0\n:"). v3 ACCEPTS it, keeping ONLY the leading
		// scalar and silently dropping the `:` content; v4 REJECTS the malformed
		// document. Distinct class so tolerating it does not tolerate other v4
		// syntax rejections.
		return side + ":doc-start"
	case strings.Contains(msg, "did not find expected key"):
		// A mapping entry whose implicit key is EMPTY (a line starting with the
		// value indicator `:`, e.g. ":", ": ", "- :"). v3 rejects it here; v4
		// accepts it as a null key. Kept distinct from the generic syntax class so
		// tolerating it does NOT tolerate every other v3 syntax rejection.
		return side + ":empty-implicit-key"
	case strings.Contains(msg, "did not find expected") || strings.Contains(msg, "could not find expected"):
		return side + ":syntax"
	case strings.Contains(msg, "control characters are not allowed"):
		return side + ":control-char"
	case strings.Contains(msg, "mapping values are not allowed"):
		return side + ":mapping-context"
	default:
		return side + ":other"
	}
}

// classifyYAMLV4ValueSplit names a decoded-value divergence class. It is
// structural, not string-based: two decoded values are compared leaf by leaf,
// and if EVERY place they differ is exactly "v3 produced nil where v4 produced
// an empty string" (with identical structure otherwise), the class is the known,
// justified non-specific-tag divergence (see EXPECTED-DIFFERENCES). Any other
// shape of difference — a different number, a different key set, a non-empty
// string mismatch — falls through to the generic "value-mismatch", which is NOT
// in the table and therefore fails the target.
func classifyYAMLV4ValueSplit(v3val, v4val any) string {
	if diffs, ok := nilVsEmptyStringOnly(v3val, v4val); ok && diffs > 0 {
		return "nonspecific-tag-empty-scalar"
	}
	return "value-mismatch"
}

// nilVsEmptyStringOnly reports whether a and b are structurally identical except
// that wherever they differ, a is nil and b is "" (the v3→v4 non-specific-`!`
// resolution change). It returns the count of such differing leaves and whether
// EVERY difference matched that exact shape. It walks maps and slices via
// reflection so it handles BOTH the map shapes yaml decodes an `any` document
// into — map[string]any (all-string keys) and map[any]any (a non-string key such
// as the int key in "0: !"). A count of 0 with ok=true means the values were
// fully equal (callers only consult this on a known mismatch).
func nilVsEmptyStringOnly(a, b any) (int, bool) {
	// The divergence leaf: v3 nil, v4 empty string.
	if a == nil {
		if bs, ok := b.(string); ok && bs == "" {
			return 1, true
		}
		if b == nil {
			return 0, true
		}
		return 0, false
	}
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	if ra.Kind() != rb.Kind() {
		return 0, false
	}
	switch ra.Kind() {
	case reflect.Map:
		if ra.Len() != rb.Len() {
			return 0, false
		}
		total := 0
		for _, k := range ra.MapKeys() {
			bval := rb.MapIndex(k)
			if !bval.IsValid() {
				return 0, false
			}
			n, ok := nilVsEmptyStringOnly(ra.MapIndex(k).Interface(), bval.Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	case reflect.Slice, reflect.Array:
		if ra.Len() != rb.Len() {
			return 0, false
		}
		total := 0
		for i := range ra.Len() {
			n, ok := nilVsEmptyStringOnly(ra.Index(i).Interface(), rb.Index(i).Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if reflect.DeepEqual(a, b) {
			return 0, true
		}
		return 0, false
	}
}

const yamlV4BudgetPath = "testdata/resguard-yaml-v4.json"

// yamlV4CalibrationCorpus is the benign corpus the bounded-work budget is
// calibrated on: a spread of real YAML shapes PLUS one legitimately-large benign
// document (deeply NOT a bomb — a flat ~6 KiB mapping of distinct keys, input ≈
// work, so the absolute/per-byte ceilings reflect the real maximum a benign
// document of that size costs, not just the tiny seeds).
func yamlV4CalibrationCorpus() [][]byte {
	out := [][]byte{
		[]byte("x: 1\n"),
		[]byte("a:\n  b:\n    c: 1\n"),
		[]byte("- 1\n- 2\n- 3\n- 4\n- 5\n"),
		[]byte("anchor: &a 1\nref: *a\nref2: *a\n"),
		[]byte("n: .nan\ni: .inf\nf: 3.14159\n"),
		[]byte("s: 2020-01-02\nt: 2020-01-02T03:04:05Z\n"),
		[]byte("block: |\n  line one\n  line two\n  line three\n"),
	}
	// One legitimately-large benign document sized near the 8 KiB input cap, so
	// the absolute alloc ceiling is calibrated against the largest benign document
	// the target will ever see (not just the tiny seeds) — the same discipline as
	// backupfmt's large-benign-archive sample (INV-RES-absmax-for-decompression).
	var sb strings.Builder
	for i := range 450 {
		fmt.Fprintf(&sb, "key_%04d: value_%04d\n", i, i)
	}
	out = append(out, []byte(sb.String()))
	return out
}

// calibrateYAMLV4 derives the bounded-work budget from the benign corpus. alloc/
// mallocs/live-heap stay on the per-byte slope (the right model for parser work:
// cost scales with input size, and only SUPER-linear growth — an amplifier — is a
// finding). The parse touches no disk/net/sleep/log/DB, so those meters never
// fire and Calibrate leaves them unbudgeted (Check then treats them as not-metered,
// never a spurious fail).
func calibrateYAMLV4(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, data := range yamlV4CalibrationCorpus() {
		// Measure each seed through BOTH libraries so the budget bounds the max of
		// the two caps (the oracle checks each library against this one budget).
		for range 4 {
			p3 := resguard.New(tb, resguard.Options{SampleEvery: 1})
			var v any
			costs = append(costs, p3.Measure(len(data), func() { _ = v3yaml.Unmarshal(data, &v) }))
			p4 := resguard.New(tb, resguard.Options{SampleEvery: 1})
			var w any
			costs = append(costs, p4.Measure(len(data), func() { _ = v4yaml.Unmarshal(data, &w) }))
		}
	}
	b := resguard.Calibrate("yaml_v4_differential", costs, resguard.DefaultFactor)
	// A YAML parse has a large FIXED per-call overhead (~270 KiB alloc even for a
	// 20-byte input), which inflates the per-byte slope so badly that the slope
	// ceiling never fires on a real amplifier. The amplification class here is
	// scale-invariant (an accepted alias fan-out materialises N copies regardless
	// of the document's byte size), so judge the memory meters by an ABSOLUTE
	// ceiling (p99·factor over a corpus that includes the largest benign doc),
	// exactly as backupfmt does for decompression (INV-RES-absmax-for-decompression).
	// cpu/wall stay advisory; mallocs/alloc go absolute.
	b.UseAbsolute("alloc_bytes", "mallocs")
	// live_heap is the WHOLE-PROCESS live heap after a forced GC — it is NOT a
	// per-input delta, so under a long fuzz run (or -parallel) it reflects
	// ~100 MiB of unrelated test-binary/coverage heap and false-fires on a 28-byte
	// input. Only alloc_bytes and mallocs (ReadMemStats deltas around the single
	// Unmarshal) are attributable to one input, so live_heap is dropped as a fatal
	// meter here. (Confirmed empirically: DF2 smoke run, live_heap=106 MiB for a
	// 28-byte input.)
	delete(b.Meters, "live_heap")
	return b
}

// loadYAMLV4Budget loads the committed budget, falling back to an in-process
// calibration if the file is absent (so the target still runs before the budget
// is committed; a committed budget is deterministic across runs).
func loadYAMLV4Budget(tb testing.TB) resguard.Budget {
	tb.Helper()
	if b, err := resguard.LoadBudget(yamlV4BudgetPath); err == nil {
		return b
	}
	return calibrateYAMLV4(tb)
}

// TestResguardYAMLV4Calibrate regenerates the committed budget when
// RESGUARD_CALIBRATE=1; otherwise it asserts calibration produces an alloc budget.
func TestResguardYAMLV4Calibrate(t *testing.T) {
	b := calibrateYAMLV4(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(yamlV4BudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", yamlV4BudgetPath, b.Summary())
	}
}

