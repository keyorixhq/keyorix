package libconformance

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
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
		"x: 1\nx: 2\n",                          // duplicate key (both expected to reject)
		"- 1\n- 2\n- 3\n",                       // sequence
		"a:\n  b:\n    c: 1\n",                  // nested maps
		"foo: !!str 123\n",                      // explicit tag
		"n: .nan\ni: .inf\n",                    // float specials (NaN re-encode parity)
		"big: 0x7fffffffffffffff\n",             // hex int
		"t: true\nf: no\ny: yes\n",              // yaml 1.1 vs 1.2 bools
		"o: 0o17\n",                             // octal 1.2
		"o: 017\n",                              // octal leading-zero
		"v: 0b101\n",                            // binary
		"e: 1_000\n",                            // underscore digits
		"s: 2020-01-02\n",                       // timestamp
		"anchor: &a 1\nref: *a\n",               // anchor/alias
		"merge: &m {a: 1}\nd: {<<: *m, b: 2}\n", // merge key
		"key: |\n  multi\n  line\n",             // block scalar
		"? [a, b]\n: val\n",                     // complex mapping key (both reject)
		"!",                                     // non-specific tag on empty scalar (v3 null / v4 "")
		"! 00",                                  // ! on NON-empty scalar: v3 int 0 / v4 "00" (D12)
		"! true",                                // ! on bool-looking scalar: v3 bool / v4 "true" (D12)
		"! null",                                // ! on null text: v3 nil / v4 "null" (D12)
		"! 1.5",                                 // ! on float-looking scalar: v3 1.5 / v4 "1.5" (D12)
		"a: ! 123",                              // ! on non-empty under a key (D12)
		"- ! 00",                                // ! on non-empty in a sequence (D12)
		"! abc",                                 // NOT a split: ! on a string-resolving scalar agrees
		"! : 00",                                // ! on an empty KEY: v3 {nil:0} / v4 {"":"00"} (D17 structural)
		"! 00 : x",                              // ! on a non-empty KEY (D17 structural)
		"&a:b",                                  // colon in anchor name: v3 ":b" / v4 nil (D18)
		"&00:00000",                             // colon in anchor name (D18)
		"k: &00:00000",                          // colon in anchor name under a key (D18)
		"a: !\nb: !!str\n",                      // mixed: ! diverges, !!str agrees
		":",                                     // empty implicit key (v3 rejects / v4 null key)
		"- :\n",                                 // empty implicit key inside a sequence
		"::",                                    // NOT a split: both accept (key "::")
		"0: !",                                  // ! on empty scalar under an INT key (map[any]any)
		"\x7f",                                  // DEL control char (v3 rejects / v4 accepts)
		"k: a\x80b\n",                           // C1 control embedded in a scalar value
		"0\n:",                                  // scalar then ':' next line (v3 accepts+truncates / v4 rejects)
		"0: !,",                                 // flow char in tag suffix (v3 lenient / v4 rejects)
		"!<a,b>",                                // NOT a split: verbatim tag accepted by both
		"|#0",                                   // comment without preceding whitespace (v3 lenient / v4 rejects)
		"\t",                                    // leading tab (v3 rejects / v4 accepts as nil)
		"|\n00",                                 // under-indented block scalar (v3 drops to "" / v4 keeps "00")
		"|\n  00",                               // NOT a split: properly indented block scalar agrees
		"o: &!0000",                             // anchor name with '!' (v3 rejects / v4 lenient)
		"- -0",                                  // -0: v3 int 0 / v4 float -0.0
		"-0:",                                   // -0 as a KEY: v3 int-0 key / v4 float-negzero key (D19)
		"|\n\"",                                 // block scalar + lone quote: v3 rejects EOS / v4 accepts (D20)
		"|\n%0",                                 // block scalar + %0: v3 rejects directive / v4 accepts (D21)
		"<<",                                    // bare merge key: v3 "<<" / v4 drops to nil (D22)
		"a: <<",                                 // merge key w/o map value: v3 keeps / v4 drops entry (D22)
		"0: {0:} ",                              // flow-map colon no space: v3 key "0:" / v4 key 0 (D23)
		"{0\n:}",                                // key continued onto the `:` line (v3 key "0 :" / v4 key 0, D23)
		"0: {0\n:}",                             // same, nested: v3 accepts / v4 rejects (D36)
		"|\n%0Ʒ",                                // directive name starting with a non-letter (D21)
		"\r! 0",                                 // ! after a bare CR line break (D12)
		"{!}",                                   // flow-context tag w/o whitespace (v3 rejects / v4 accepts)
		"[!x]",                                  // tagged empty node in flow seq (v3 rejects / v4 "")
		"[0: !]",                                // tagged empty value in flow seq (v3 rejects / v4 "")
		"[0: !t 1]",                             // NOT a split: tag on NON-empty flow scalar agrees
		"[: 1]",                                 // empty key in flow seq (v3 rejects / v4 null key)
		"'': empty-key\n",                       // empty key
		"a: 1\nb: {c: 2, c: 3}\n",               // nested duplicate key
		"---\na: 1\n---\nb: 2\n",                // multi-document (single-value decode)
		"key: =\n",                              // the '=' value
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
			if class == "v4-rejects:mapping-context" && accept3 && isFlowMultilineKeySplit(data) {
				class = "v4-rejects:flow-multiline-key"
			}
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
			class := classifyYAMLV4ValueSplit(data, v3val, v4val)
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
	case strings.Contains(msg, "expected whitespace or line break"):
		// A tag/node in flow context without the whitespace v3 requires after it
		// (e.g. "{!}" — a `!`-tagged empty node inside a flow mapping). v3 rejects;
		// v4 is lenient and accepts. v4 accepts what v3 rejects (benign flow leniency).
		return side + ":flow-ws"
	case strings.Contains(msg, "expected alphabetic or numeric character"):
		// An anchor/alias name containing a character v3 forbids there (e.g. "&!0000"
		// — an anchor name with `!`). v3 rejects the non-alphanumeric anchor char; v4
		// is lenient and accepts it. v4 accepts what v3 rejects (benign — anchor name).
		return side + ":anchor-char"
	case strings.Contains(msg, "tab character"):
		// A tab used as block scalar indentation (`|\n\t`). YAML spec requires spaces for
		// indentation; v3 enforces this ("found a tab character where an indentation space
		// is expected"). v4 is lenient and accepts it. Same family as D7 (token-start), but
		// for block-scalar context. Distinct error message, distinct class.
		return side + ":tab-indent"
	case strings.Contains(msg, "cannot start any token"):
		// A leading character v3's scanner refuses to start a token with — notably a
		// bare TAB ("\t"), which v4 accepts as an empty document (nil). Other chars
		// with this v3 error (`@`, backtick) are rejected by BOTH, so only the
		// leading-TAB-ish case actually splits.
		return side + ":token-start"
	case strings.Contains(msg, "',' or ']'"):
		// A tag (`!`, `!local`) applied to an EMPTY node inside a FLOW SEQUENCE
		// (`[!x]`, `[0: !]`, `[a: !x]`). v3's flow scanner cannot handle a tag with
		// no node content before the `,`/`]` and rejects ("did not find expected ','
		// or ']'"); v4 accepts it, resolving the tagged-empty node to "". A tag on a
		// NON-empty flow scalar (`[0: !t 1]`) is accepted by BOTH, so only the
		// tagged-EMPTY-in-flow case splits. Same v4-lenient flow family as D11 (`{!}`),
		// different container/error. v4 accepts what v3 rejects.
		return side + ":flow-seq-tagged-empty"
	case strings.Contains(msg, "did not find expected node content"):
		// An EMPTY key/node in FLOW context (`[: 1]`). v3 rejects ("did not find
		// expected node content"); v4 accepts it as a null-keyed single-pair map
		// element. The flow-context analogue of D2 (block empty-implicit-key). v4
		// accepts what v3 rejects.
		return side + ":flow-node-content"
	case strings.Contains(msg, "comment or line break"):
		// A block scalar header (`|`/`>`) followed immediately by a non-whitespace,
		// non-modifier character (e.g. `|\n|A`). v3 re-scans the second `|` as a new
		// block scalar header and rejects because `A` is not a valid modifier or line
		// break. v4 treats `|A` as block scalar content at column 0. The error is
		// "did not find expected comment or line break"; must be placed BEFORE the
		// generic "did not find expected" / "could not find expected" :syntax catch.
		return side + ":block-header"
	case strings.Contains(msg, "merge requires") || strings.Contains(msg, "map merge"):
		// The `<<` merge-key with an INVALID merge value (`{<<:}`, `{<<: null}`). v4
		// enforces merge-key semantics and rejects when the value is not a map or
		// sequence of maps ("map merge requires map or sequence of maps as the value").
		// v3 treats `<<` as a plain key (null value) and accepts. This is the REJECT
		// direction of D22 (which covers the ACCEPT case where v4 silently drops data).
		return side + ":merge-value"
	case strings.Contains(msg, "directive") || strings.Contains(msg, "non-alphabetical character"):
		// "found unexpected non-alphabetical character" is the scanner's directive-NAME
		// error (`|\n%0Ʒ`: the name after `%` starts with a non-letter); same D21 cause.
		// Keep this case BEFORE the generic "could not find expected" / "did not find
		// expected" catch below: "could not find expected directive name" (bare `%` in
		// block-scalar context) contains BOTH substrings; the specific directive class
		// must win over the generic :syntax class.
		// A `%`-introduced directive v3 rejects — e.g. under-indented block-scalar
		// content `%0` (`|\n%0`) that v3 re-scans as a document directive ("found
		// unknown directive name"), or bare `%` ("could not find expected directive
		// name"). v3 REJECTS; v4 is lenient and ACCEPTS.
		return side + ":directive"
	case strings.Contains(msg, "did not find expected") || strings.Contains(msg, "could not find expected"):
		return side + ":syntax"
	case strings.Contains(msg, "control characters are not allowed"):
		return side + ":control-char"
	case strings.Contains(msg, "not allowed in a yaml tag"):
		// A flow indicator (`,` `[` `]`) in a non-verbatim tag suffix (e.g. "!,",
		// "!tag[", "!a,b c"). v4 strictly rejects it (flow chars are not valid tag
		// characters); v3 leniently ends the tag before the flow char and treats the
		// rest as content. `!{`/`!}` are rejected by BOTH; verbatim `!<a,b>` accepted
		// by BOTH — only the non-verbatim flow-char suffix splits.
		return side + ":tag-char"
	case strings.Contains(msg, "mapping values are not allowed"):
		return side + ":mapping-context"
	case strings.Contains(msg, "mapping keys are not allowed"):
		// A `?` complex-key / mapping-key indicator in a context v3 forbids — e.g.
		// `&0?` (an anchor followed by `?`). v3 REJECTS ("mapping keys are not allowed
		// in this context"); v4 is lenient and ACCEPTS. v4 accepts what v3 rejects.
		return side + ":mapping-key-context"
	case strings.Contains(msg, "unexpected end of stream"):
		// A truncated / unterminated construct — e.g. a block scalar followed by a
		// lone `"` at column 0 (`|\n"`), which v3 reads as an unterminated
		// double-quoted scalar. v3 REJECTS ("found unexpected end of stream"); v4 is
		// lenient and ACCEPTS. v4 accepts what v3 rejects (same strictness direction
		// as D2/D3 — the migration-hazard direction) but benignly on malformed input.
		return side + ":unexpected-eos"
	case strings.Contains(msg, "comment without preceding whitespace"):
		// A `#` not preceded by whitespace (e.g. "|#0", "a#b" in some contexts). The
		// YAML spec requires a comment to be preceded by whitespace; v4 enforces this
		// and rejects, v3 is lenient. v4 is the more spec-correct side.
		return side + ":comment-ws"
	case strings.Contains(msg, "found an indentation indicator equal to 0"):
		// A block scalar with an explicit indentation indicator of 0 (e.g. `>0` on the
		// first content line). YAML spec §8.1 requires the indentation indicator to be
		// 1–9 if present; zero is explicitly forbidden. v3 enforces this and rejects;
		// v4 is lenient and accepts. Found by the DF3 multi-doc fuzzer at `>\n>0` (the
		// second document). v3 is the stricter/safer side here.
		return side + ":indentation-indicator"
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
func classifyYAMLV4ValueSplit(data []byte, v3val, v4val any) string {
	if diffs, ok := nilVsEmptyStringOnly(v3val, v4val); ok && diffs > 0 {
		return "nonspecific-tag-empty-scalar"
	}
	// Under-indented block-scalar content: v3 drops it to the empty string where v4
	// captures it. Recognised only when (a) every differing leaf is v3-"" vs a
	// NON-empty v4 string, and (b) the input actually carries a block-scalar header
	// (`|`/`>`), so a value divergence of this exact shape from any OTHER cause is
	// not absorbed.
	if diffs, ok := v3EmptyVsV4NonEmptyStringOnly(v3val, v4val); ok && diffs > 0 && inputHasBlockScalarHeader(data) {
		return "block-scalar-underindent"
	}
	// Block-scalar end-of-stream clip difference (D27): when the last content line of a
	// block scalar is whitespace-only (above the indent level) and the input ends without a
	// terminal newline, v3 omits the clip-chomping newline while v4 adds it. The shape is
	// "every differing leaf has v4val == v3val + newline". Guarded by: (a) block-scalar
	// header present, (b) input ends without `\n`/`\r`. Adding a trailing newline resolves
	// the ambiguity (confirmed: `|\n 000000\n  \n` → both agree at `"000000\n \n"`).
	if diffs, ok := v3StringVsV4StringPlusNewlineOnly(v3val, v4val); ok && diffs > 0 &&
		inputHasBlockScalarHeader(data) && !bytes.HasSuffix(data, []byte{'\n'}) && !bytes.HasSuffix(data, []byte{'\r'}) {
		return "block-scalar-eos-clip"
	}
	// The literal `-0`: v3 resolves it to int 0, v4 to float64 negative zero.
	if diffs, ok := negZeroIntVsFloatOnly(v3val, v4val); ok && diffs > 0 {
		return "negative-zero-int-vs-float"
	}
	// The non-specific tag `!` applied to a NON-empty scalar (`! 00`, `! true`,
	// `! 1.5`, …). v3 ignores the `!` and applies its normal implicit schema (so
	// `! 00` → int 0, `! true` → bool); v4 treats `!` as forcing the failsafe
	// `!!str` resolution and keeps the raw string (`"00"`, `"true"`). This is the
	// same root cause as the empty-scalar D1 class, generalised to non-empty
	// scalars. Recognised ONLY when every differing leaf is "v4 kept the raw
	// string s, and v3's value is exactly the v3 implicit resolution of s" AND the
	// input carries a non-specific `!` tag — so an unrelated value divergence is
	// not absorbed.
	if diffs, ok := nonspecificTagNonEmptyScalarOnly(v3val, v4val); ok && diffs > 0 && inputHasNonSpecificTag(data) {
		return "nonspecific-tag-nonempty-scalar"
	}
	// A flow-mapping entry whose `:` is immediately followed by `}` or `,` with no
	// space (`{0:}`): v3 keeps the `:` IN the key (key `"0:"`), v4 treats the `:` as
	// the key/value separator (key `0`, null value). Recognised causally: inserting a
	// space after such a `:` makes v3 agree with v4 (and v4 is unchanged).
	if isFlowColonNoSpaceDivergence(data, v3val, v4val) {
		return "flow-map-colon-nospace"
	}
	// The `<<` merge-key indicator used where it is not a valid map-merge (`<<`,
	// `a: <<`, `- <<`): v3 keeps the literal string "<<", v4 treats it as a merge
	// directive and SILENTLY DROPS the entry/element (empty container / nil).
	// Recognised causally: single-quoting every `<<` (forcing a plain string in
	// BOTH) makes the two agree and reproduces v3's value.
	if strings.Contains(string(data), "<<") && isMergeKeyDivergence(data, v3val) {
		return "merge-key-handling"
	}
	// The `-0` int-vs-float divergence (D10) landing in a KEY position (`-0:`),
	// where v3's key is int 0 and v4's is float negative zero, so the maps do not
	// align and the value-only walker falls through. Recognised by negZeroEq, scoped
	// to inputs literally containing `-0`.
	if strings.Contains(string(data), "-0") && negZeroEq(v3val, v4val) {
		return "negative-zero-structural"
	}
	// A flow-SEQUENCE entry whose `:` is immediately followed by `]` with no space
	// (`[0:]`): v3 keeps the `:` IN the value (value `"0:"`), v4 treats the `:` as
	// the key/value separator (key `0`, null value). The flow-SEQUENCE analogue of
	// D23 (`{0:}`). Recognised causally: inserting a space before `]` makes v3 agree
	// with v4 (and v4 is unchanged).
	if isFlowSeqColonNoSpaceDivergence(data, v3val, v4val) {
		return "flow-seq-colon-nospace"
	}
	// A colon inside an anchor NAME (`&a:b`, `&00:00000`). v3 ends the anchor name
	// at the `:` (so `&a:b` → anchor `a`, content ":b"); v4 absorbs the `:` into the
	// name (anchor `a:b`, EMPTY node → nil). Both accept, values differ.
	if isAnchorColonBoundaryDivergence(data, v3val, v4val) {
		return "anchor-name-colon-boundary"
	}
	// Structural nonspecific-tag divergence that the value-only walkers above miss:
	// the `!`-tag re-resolution landing in a KEY position (`! : 00`, `! 00: x`),
	// where v3 and v4 produce DIFFERENT map keys (v3 nil / typed vs v4 raw string)
	// so the entries cannot be paired by key. nonspecificTagEq pairs entries across
	// the tag transformation at any position; scoped to inputs carrying a `!` tag.
	if inputHasNonSpecificTag(data) && nonspecificTagEq(v3val, v4val) {
		return "nonspecific-tag-structural"
	}
	// YAML 1.1 binary integer literal (`0b+0`, `0b1`, `0b101`): v3 (YAML 1.1) decodes
	// the `0b` prefix as a binary integer; v4 (YAML 1.2) has no binary number form and
	// keeps the token as a string. The structural check handles both top-level (bare
	// scalar) and nested (value inside a map or sequence) positions; a re-parse
	// confirmation in yaml11BinaryIntVsStringOnly prevents absorbing a genuine mismatch.
	if diffs, ok := yaml11BinaryIntVsStringOnly(v3val, v4val); ok && diffs > 0 {
		return "yaml11-binary-int"
	}
	return "value-mismatch"
}

// isFlowColonNoSpaceDivergence causally confirms the flow-mapping `:`-no-space
// divergence (`{0:}`): inserting a space after every `:}`/`:, ` turns the disputed
// `:` into an unambiguous separator. If after that v4 is UNCHANGED (it already read
// the `:` as a separator) and v3 now equals v4, then v3's keeping of the `:` in the
// key was the sole cause. A genuine divergence that merely contains `:}` is not
// absorbed (v4 would change, or v3 would not come to match).
func isFlowColonNoSpaceDivergence(data []byte, v3val, v4val any) bool {
	s := string(data)
	spaced := strings.ReplaceAll(strings.ReplaceAll(s, ":}", ": }"), ":,", ": ,")
	if spaced == s {
		return false
	}
	if flowColonRepairAgrees(spaced, v3val, v4val) {
		return true
	}
	// The key may be a plain scalar continued onto the line holding the `:` (`{0\n:}`):
	// v3 folds the break into the key (`"0 :"`), and also rejects `{0\n: }`, so the
	// space-only repair cannot agree. Join the break before the `:` as well.
	joined := flowColonBreakRe.ReplaceAllString(s, " : $1")
	if joined == s {
		return false
	}
	return flowColonRepairAgrees(flowColonSpaceRe.ReplaceAllString(joined, ": $1"), v3val, v4val)
}

var (
	flowColonBreakRe = regexp.MustCompile(`[ \t]*\r?\n[ \t]*:([},])`)
	flowColonSpaceRe = regexp.MustCompile(`:([},])`)
)

// isFlowMultilineKeySplit causally confirms the accept/reject form of the D23 break
// variant (`0: {0\n:}`): v3 accepts, v4 rejects. Joining the break before the `:` and
// spacing it makes BOTH libraries accept and decode identically, so the line break in
// the key was the sole cause. A rejection from any other cause is not absorbed.
func isFlowMultilineKeySplit(data []byte) bool {
	s := string(data)
	joined := flowColonBreakRe.ReplaceAllString(s, " : $1")
	if joined == s {
		return false
	}
	joined = flowColonSpaceRe.ReplaceAllString(joined, ": $1")
	var m3, m4 any
	if v3yaml.Unmarshal([]byte(joined), &m3) != nil || v4yaml.Unmarshal([]byte(joined), &m4) != nil {
		return false
	}
	c3, e3 := v3yaml.Marshal(m3)
	c4, e4 := v3yaml.Marshal(m4)
	return e3 == nil && e4 == nil && reflect.DeepEqual(c3, c4)
}

// flowColonRepairAgrees reports whether the repaired input mod decodes identically in
// v3 and v4 and v4's decoding is unchanged from the original v4val.
func flowColonRepairAgrees(mod string, v3val, v4val any) bool {
	var m3, m4 any
	if v3yaml.Unmarshal([]byte(mod), &m3) != nil || v4yaml.Unmarshal([]byte(mod), &m4) != nil {
		return false
	}
	cm3, e3 := v3yaml.Marshal(m3)
	cm4, e4 := v3yaml.Marshal(m4)
	co4, e4b := v3yaml.Marshal(v4val)
	if e3 != nil || e4 != nil || e4b != nil {
		return false
	}
	// v4 unchanged by the space, and v3 now matches v4.
	return reflect.DeepEqual(cm4, co4) && reflect.DeepEqual(cm3, cm4)
}

// isFlowSeqColonNoSpaceDivergence causally confirms the flow-SEQUENCE `:`-no-space
// divergence (`[0:]`): a `:` immediately followed by `]` acts as a key/value separator
// in v4 but is kept inside the value string by v3. Inserting a space before `]` resolves
// the ambiguity. If after that v4 is UNCHANGED (it already read the `:` as a separator)
// and v3 now agrees with v4, then v3's keeping of the `:` in the value was the sole cause.
// A genuine divergence that merely contains `:]` is not absorbed (v4 would change, or
// v3 would not come to match). The flow-SEQUENCE counterpart of isFlowColonNoSpaceDivergence.
func isFlowSeqColonNoSpaceDivergence(data []byte, v3val, v4val any) bool {
	s := string(data)
	mod := strings.ReplaceAll(s, ":]", ": ]")
	if mod == s {
		return false
	}
	var m3, m4 any
	if v3yaml.Unmarshal([]byte(mod), &m3) != nil || v4yaml.Unmarshal([]byte(mod), &m4) != nil {
		return false
	}
	cm3, e3 := v3yaml.Marshal(m3)
	cm4, e4 := v3yaml.Marshal(m4)
	co4, e4b := v3yaml.Marshal(v4val)
	if e3 != nil || e4 != nil || e4b != nil {
		return false
	}
	// v4 unchanged by the space, and v3 now matches v4.
	return reflect.DeepEqual(cm4, co4) && reflect.DeepEqual(cm3, cm4)
}

// isMergeKeyDivergence causally confirms a `<<` merge-key divergence: single-quote
// every `<<` in the input (forcing it to be a plain string in BOTH libraries) and
// require that v3 then reproduces its ORIGINAL value. If quoting the merge
// indicator removes the divergence, `<<` merge-handling was the sole cause, so a
// genuine divergence that merely contains `<<` is never absorbed. (We only need to
// check v3 here: the caller already knows v3 and v4 disagreed on the original; if
// quoting makes v3 unchanged, v4 — which has no live caller — simply stopped
// dropping the entry, i.e. the drop was the whole divergence.)
func isMergeKeyDivergence(data []byte, v3val any) bool {
	quoted := strings.ReplaceAll(string(data), "<<", "'<<'")
	if quoted == string(data) {
		return false
	}
	var q3, q4 any
	if v3yaml.Unmarshal([]byte(quoted), &q3) != nil || v4yaml.Unmarshal([]byte(quoted), &q4) != nil {
		return false
	}
	cq3, e3 := v3yaml.Marshal(q3)
	cq4, e4 := v3yaml.Marshal(q4)
	if e3 != nil || e4 != nil || !reflect.DeepEqual(cq3, cq4) {
		return false
	}
	co3, err := v3yaml.Marshal(v3val)
	return err == nil && reflect.DeepEqual(co3, cq3)
}

// negZeroEq reports whether a (v3) and b (v4) are identical up to the `-0`
// int-vs-float resolution (D10) applied at ANY position — value OR key, nested —
// pairing map entries so a differing KEY (v3 int 0 vs v4 float negative zero) is
// matched. It never equates a genuine diff: a differing leaf must be exactly int 0
// (v3) vs a float negative zero (v4).
func negZeroEq(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	if ai, ok := a.(int); ok && ai == 0 {
		if bf, ok := b.(float64); ok && bf == 0 && math.Signbit(bf) {
			return true
		}
	}
	if a == nil || b == nil {
		return false
	}
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	if ra.Kind() != rb.Kind() {
		return false
	}
	switch ra.Kind() {
	case reflect.Map:
		if ra.Len() != rb.Len() {
			return false
		}
		bkeys := rb.MapKeys()
		used := make([]bool, len(bkeys))
		for _, k3 := range ra.MapKeys() {
			v3v := ra.MapIndex(k3).Interface()
			matched := false
			for i, k4 := range bkeys {
				if used[i] {
					continue
				}
				if negZeroEq(k3.Interface(), k4.Interface()) && negZeroEq(v3v, rb.MapIndex(k4).Interface()) {
					used[i], matched = true, true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		if ra.Len() != rb.Len() {
			return false
		}
		for i := range ra.Len() {
			if !negZeroEq(ra.Index(i).Interface(), rb.Index(i).Interface()) {
				return false
			}
		}
		return true
	default:
		return leafEq(a, b)
	}
}

// v3AnchorTokenRe matches the anchor token as v3 scans it: `&` plus the
// anchor-name characters up to (but not including) a flow/`:`/`?`/whitespace boundary.
// `?` is included because v3 stops the anchor name before the YAML complex-key indicator
// `?` (e.g. `&0?0` → v3 reads anchor `0`, content `?0`), while v4 is more liberal
// and absorbs `?` into the anchor name.
var v3AnchorTokenRe = regexp.MustCompile(`&[^\s:,\[\]{}?]+`)

// isAnchorColonBoundaryDivergence reports whether a v3/v4 value divergence is
// caused solely by a `:` inside an anchor name — v3 ends the name at the colon,
// v4 absorbs it. It is a CAUSAL test, not a shape guess: it strips the first
// v3-anchor token (which must be immediately followed by `:` in the input, the
// disputed boundary) and requires that (a) the two libraries then AGREE on the
// stripped input, and (b) v3's value is unchanged by the strip (an unused anchor
// is just a label, so removing it must not alter v3's decode). Only when removing
// the anchor makes the divergence vanish is the anchor-name extent proven to be
// the cause, so a genuine divergence that merely contains an anchor is never
// absorbed. Scoped by construction to block context; the flow-sequence
// anchor-colon combo (`[&a:b]`) is a separate, compounded divergence left in the
// residual tail.
func isAnchorColonBoundaryDivergence(data []byte, v3val, v4val any) bool {
	// Try each anchor in the input: whichever one is immediately followed by `:` and
	// whose removal makes v3 and v4 agree (with v3 unchanged) is the causal anchor.
	// Originally only tried the first anchor; extended to try all because the
	// colon-absorbing anchor may not be the first one in the input (e.g. `&0: &0:0`
	// where the second anchor `&0:0` is the one causing the divergence).
	co3, err := v3yaml.Marshal(v3val)
	if err != nil {
		return false
	}
	for _, loc := range v3AnchorTokenRe.FindAllIndex(data, -1) {
		if loc[1] >= len(data) {
			continue
		}
		b := data[loc[1]]
		// Try `:` (D18/colon-boundary) and `?` (v4 also absorbs `?` into anchor names,
		// e.g. `&0?0` where v3 ends at `?` and v4 makes the anchor name `0?0`).
		if b != ':' && b != '?' {
			continue
		}
		stripped := append(append([]byte{}, data[:loc[0]]...), data[loc[1]:]...)
		var m3, m4 any
		if v3yaml.Unmarshal(stripped, &m3) != nil || v4yaml.Unmarshal(stripped, &m4) != nil {
			continue
		}
		c3m, e3 := v3yaml.Marshal(m3)
		c4m, e4 := v3yaml.Marshal(m4)
		if e3 != nil || e4 != nil || !reflect.DeepEqual(c3m, c4m) {
			continue
		}
		if reflect.DeepEqual(co3, c3m) {
			return true
		}
	}
	return false
}

// nonspecificTagEq reports whether a (v3) and b (v4) are identical up to the
// non-specific `!` tag rule applied at ANY scalar position — value OR key, nested
// arbitrarily. Wherever a leaf differs, b must be a string s and a must be the v3
// implicit resolution of s (the empty case a=nil,s="" included). Maps are paired
// entry-by-entry allowing the key itself to differ by the same rule, which is why
// this subsumes the KEY-position divergence the structural value-walkers (which
// look keys up directly) cannot express. It never equates a genuine value diff:
// the reparse of s must deep-equal a, so v3 `5` vs v4 `"6"` (reparse 6 ≠ 5) and
// nil vs a non-empty string both return false.
func nonspecificTagEq(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	if bs, ok := b.(string); ok {
		if a == nil && bs == "" {
			return true
		}
		var r any
		if err := v3yaml.Unmarshal([]byte(bs), &r); err == nil && reflect.DeepEqual(r, a) {
			return true
		}
		return false
	}
	if a == nil || b == nil {
		return false
	}
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	if ra.Kind() != rb.Kind() {
		return false
	}
	switch ra.Kind() {
	case reflect.Map:
		if ra.Len() != rb.Len() {
			return false
		}
		bkeys := rb.MapKeys()
		used := make([]bool, len(bkeys))
		for _, k3 := range ra.MapKeys() {
			v3v := ra.MapIndex(k3).Interface()
			matched := false
			for i, k4 := range bkeys {
				if used[i] {
					continue
				}
				if nonspecificTagEq(k3.Interface(), k4.Interface()) && nonspecificTagEq(v3v, rb.MapIndex(k4).Interface()) {
					used[i], matched = true, true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		if ra.Len() != rb.Len() {
			return false
		}
		for i := range ra.Len() {
			if !nonspecificTagEq(ra.Index(i).Interface(), rb.Index(i).Interface()) {
				return false
			}
		}
		return true
	default:
		return leafEq(a, b)
	}
}

// mapLookupByLogicalKey looks up key k (taken from map a) in map m by LOGICAL key
// value, tolerating a key-TYPE mismatch between the two maps. yaml decodes a
// mapping with all-string keys into map[string]any but a mapping with any
// non-string key into map[any]any, so comparing a v3 and a v4 document can pair a
// map[string]any against a map[any]any for the same logical mapping; a naive
// rb.MapIndex(stringKeyFromInterfaceMap) panics ("interface {} is not assignable
// to type string"). This unwraps an interface key to its concrete value (and
// relies on Go's auto-boxing for the concrete→interface direction) so the
// structural walk compares the same logical entries. It does NOT equate maps that
// genuinely differ — a missing logical key still returns ok=false; and the
// classifier is only ever reached once the canonical-marshal bytes already differ,
// where map[string]any vs map[any]any with identical entries canonicalise equal.
func mapLookupByLogicalKey(m, k reflect.Value) (reflect.Value, bool) {
	kt := m.Type().Key()
	if k.Type().AssignableTo(kt) {
		v := m.MapIndex(k)
		return v, v.IsValid()
	}
	if k.Kind() == reflect.Interface {
		if e := k.Elem(); e.IsValid() && e.Type().AssignableTo(kt) {
			v := m.MapIndex(e)
			return v, v.IsValid()
		}
	}
	return reflect.Value{}, false
}

// nonSpecificTagRe matches a standalone non-specific `!` tag: a `!` that is a
// complete tag token (not the `!!x` explicit-tag form, not the `!<…>` verbatim
// form, not a `!local` named tag), preceded by start-of-line or a
// whitespace/flow/indicator character and followed by whitespace (including CR)
// or end-of-line. CR (`\r`) is valid YAML whitespace (s-white) and is a legal
// separator between `!` and its following scalar (`!\r0` ≡ `! 0` to both parsers).
var nonSpecificTagRe = regexp.MustCompile(`(?m)(^|[ \t\r:\-\[\]{},])!([ \t\r]|$)`)

func inputHasNonSpecificTag(data []byte) bool {
	return nonSpecificTagRe.Match(data)
}

// nonspecificTagNonEmptyScalarOnly reports whether a (v3) and b (v4) are
// structurally identical except that wherever they differ, b is a NON-empty
// string s and a is exactly the v3 implicit resolution of s (i.e. v4 kept the
// `!`-tagged scalar as a raw string while v3 resolved it by the normal schema).
// It returns the count of such differing leaves and whether every difference
// matched that exact shape. The empty-string case (a=nil, b="") is intentionally
// NOT handled here — that is the separate D1 nilVsEmptyStringOnly class.
func nonspecificTagNonEmptyScalarOnly(a, b any) (int, bool) {
	if bs, ok := b.(string); ok {
		if bs == "" {
			// Empty-string leaf belongs to D1 (nil-vs-""), not this class; only
			// accept it here if a is an identical empty string (no divergence).
			if as, ok := a.(string); ok && as == "" {
				return 0, true
			}
			return 0, false
		}
		if as, ok := a.(string); ok && as == bs {
			return 0, true // identical non-empty strings — not a divergence
		}
		// The divergence shape: a must equal the v3 implicit resolution of s.
		var resolved any
		if err := v3yaml.Unmarshal([]byte(bs), &resolved); err == nil && reflect.DeepEqual(resolved, a) {
			return 1, true
		}
		return 0, false
	}
	if a == nil || b == nil {
		return 0, reflect.DeepEqual(a, b)
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
			bval, bok := mapLookupByLogicalKey(rb, k)
			if !bok {
				return 0, false
			}
			n, ok := nonspecificTagNonEmptyScalarOnly(ra.MapIndex(k).Interface(), bval.Interface())
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
			n, ok := nonspecificTagNonEmptyScalarOnly(ra.Index(i).Interface(), rb.Index(i).Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if leafEq(a, b) {
			return 0, true
		}
		return 0, false
	}
}

// negZeroIntVsFloatOnly reports whether a and b are structurally identical except
// that wherever they differ, a is int 0 and b is a float64 negative zero (the
// `-0` resolution change).
func negZeroIntVsFloatOnly(a, b any) (int, bool) {
	if ai, ok := a.(int); ok {
		if bf, ok := b.(float64); ok {
			if ai == 0 && bf == 0 && math.Signbit(bf) {
				return 1, true
			}
			return 0, false
		}
		if bi, ok := b.(int); ok && ai == bi {
			return 0, true
		}
		return 0, false
	}
	if a == nil || b == nil {
		return 0, reflect.DeepEqual(a, b)
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
			bval, bok := mapLookupByLogicalKey(rb, k)
			if !bok {
				return 0, false
			}
			n, ok := negZeroIntVsFloatOnly(ra.MapIndex(k).Interface(), bval.Interface())
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
			n, ok := negZeroIntVsFloatOnly(ra.Index(i).Interface(), rb.Index(i).Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if leafEq(a, b) {
			return 0, true
		}
		return 0, false
	}
}

// blockScalarHeaderRe matches a block-scalar header (`|` or `>`, optional indent
// digit, optional chomping `+`/`-`) at the end of a line, optionally after a
// `key:` or `- ` indicator or leading whitespace — the shape that introduces
// literal/folded content. `^[ \t]*` covers indented block scalars (e.g. ` |\r0`).
// `\r` (CR) is an alternative line terminator alongside `$` (which in Go's (?m)
// mode matches before `\n` but not `\r`), so `|\r0` and ` |\r0` are both
// correctly recognised as block-scalar headers followed by CR-terminated content.
var blockScalarHeaderRe = regexp.MustCompile(`(?m)(^[ \t]*|[:\-][ \t]*)[|>][0-9]*[+\-]?[ \t]*(\r|$)`)

// yaml11BinaryIntRe matches a YAML 1.1 binary integer literal: an optional leading
// sign, `0b`/`0B` prefix, an optional sign after the prefix, then one or more
// binary digits or underscores. YAML 1.1 supports `0b[0-1_]+`; some implementations
// (v3 included) also allow a sign between the prefix and the digits (e.g. `0b+0`).
// YAML 1.2 (v4) dropped binary literals; v3 decodes these as integers, v4 as strings.
var yaml11BinaryIntRe = regexp.MustCompile(`^[-+]?0[bB][-+]?[0-1_]+$`)

func inputHasBlockScalarHeader(data []byte) bool {
	return blockScalarHeaderRe.Match(data)
}

// yaml11BinaryIntVsStringOnly reports whether a (v3) and b (v4) are structurally
// identical except that wherever they differ, a is an integer and b is a string
// matching yaml11BinaryIntRe — the YAML 1.1 binary int that v3 decoded as an integer
// but v4 kept as a string. A re-parse confirmation (v3-decode of b equals a) prevents
// a genuine int-vs-binary-string mismatch from being absorbed. Handles both top-level
// and nested (map value / sequence element) positions.
func yaml11BinaryIntVsStringOnly(a, b any) (int, bool) {
	if ai, ok := a.(int); ok {
		if bs, ok2 := b.(string); ok2 {
			if !yaml11BinaryIntRe.MatchString(bs) {
				return 0, false
			}
			var reparsed any
			if err := v3yaml.Unmarshal([]byte(bs), &reparsed); err != nil {
				return 0, false
			}
			ri, ok3 := reparsed.(int)
			if !ok3 || ri != ai {
				return 0, false
			}
			return 1, true
		}
		if bi, ok2 := b.(int); ok2 && ai == bi {
			return 0, true
		}
		return 0, false
	}
	if reflect.DeepEqual(a, b) {
		return 0, true
	}
	if a == nil || b == nil {
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
			bval, bok := mapLookupByLogicalKey(rb, k)
			if !bok {
				return 0, false
			}
			n, ok := yaml11BinaryIntVsStringOnly(ra.MapIndex(k).Interface(), bval.Interface())
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
			n, ok := yaml11BinaryIntVsStringOnly(ra.Index(i).Interface(), rb.Index(i).Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if leafEq(a, b) {
			return 0, true
		}
		return 0, false
	}
}

// v3EmptyVsV4NonEmptyStringOnly reports whether a and b are structurally identical
// except that wherever they differ, a is the EMPTY string and b is a non-empty
// string (the block-scalar under-indentation drop). Mirrors nilVsEmptyStringOnly
// but for the "" -> non-empty shape.
func v3EmptyVsV4NonEmptyStringOnly(a, b any) (int, bool) {
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return 0, false
		}
		if as == bs {
			return 0, true
		}
		if as == "" && bs != "" {
			return 1, true
		}
		return 0, false
	}
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	if a == nil || b == nil {
		return 0, reflect.DeepEqual(a, b)
	}
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
			bval, bok := mapLookupByLogicalKey(rb, k)
			if !bok {
				return 0, false
			}
			n, ok := v3EmptyVsV4NonEmptyStringOnly(ra.MapIndex(k).Interface(), bval.Interface())
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
			n, ok := v3EmptyVsV4NonEmptyStringOnly(ra.Index(i).Interface(), rb.Index(i).Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if leafEq(a, b) {
			return 0, true
		}
		return 0, false
	}
}

// v3StringVsV4StringPlusNewlineOnly reports whether a and b are structurally
// identical except that wherever they differ, b is a string equal to a + "\n"
// (v4 adds exactly one trailing newline that v3 did not). This matches the
// block-scalar end-of-stream clip difference (D27): when a block scalar's last
// content line is whitespace-only (above indent) and the input ends without a
// terminal newline, v3 omits the clip-chomping newline and v4 adds it.
func v3StringVsV4StringPlusNewlineOnly(a, b any) (int, bool) {
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return 0, false
		}
		if as == bs {
			return 0, true
		}
		if bs == as+"\n" {
			return 1, true
		}
		return 0, false
	}
	if a == nil || b == nil {
		return 0, reflect.DeepEqual(a, b)
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
			bval, bok := mapLookupByLogicalKey(rb, k)
			if !bok {
				return 0, false
			}
			n, ok := v3StringVsV4StringPlusNewlineOnly(ra.MapIndex(k).Interface(), bval.Interface())
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
			n, ok := v3StringVsV4StringPlusNewlineOnly(ra.Index(i).Interface(), rb.Index(i).Interface())
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if leafEq(a, b) {
			return 0, true
		}
		return 0, false
	}
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
			bval, bok := mapLookupByLogicalKey(rb, k)
			if !bok {
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
		if leafEq(a, b) {
			return 0, true
		}
		return 0, false
	}
}

// leafEq is reflect.DeepEqual for a scalar leaf, except that two NaN floats are
// equal. reflect.DeepEqual(NaN, NaN) is false, so a document that carries `.nan`
// anywhere (`0: .nan\n1: !`) made every structural walker above report "not the
// known shape" and the known class fell through to "value-mismatch".
func leafEq(a, b any) bool {
	if af, ok := a.(float64); ok {
		if bf, ok := b.(float64); ok && math.IsNaN(af) && math.IsNaN(bf) {
			return true
		}
	}
	return reflect.DeepEqual(a, b)
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
