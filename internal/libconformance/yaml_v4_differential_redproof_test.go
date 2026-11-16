package libconformance

import (
	"reflect"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	v3yaml "go.yaml.in/yaml/v3"
	v4yaml "go.yaml.in/yaml/v4"
)

// yamlV4ExpectedDiff lists tolerated divergence classes between
// go.yaml.in/yaml/v3 v3.0.5 and go.yaml.in/yaml/v4 v4.0.0 (see
// FuzzYAMLV4Differential / classifyYAMLV4Split for the class vocabulary, and
// EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md for the prose slide).
//
// It is EMPTY on purpose: across the seed corpus and the fuzz run recorded in
// the DF2 report, v3.0.5 and v4.0.0 agreed on every accept/reject verdict and
// every decoded value (v4 kept Unmarshal/Marshal as compat shims over the same
// YAML 1.1/1.2 core; only error-message wording changed, which classifyYAMLV4Split
// deliberately normalises away). A NEW divergence class the fuzzer finds is a
// finding until it is triaged and justified here — an empty table is the strong
// default this whole target exists to defend.
var yamlV4ExpectedDiff = map[string]bool{
	// Non-specific tag `!` on an EMPTY scalar node. v3.0.5 resolves it to null;
	// v4.0.0 resolves it to the empty string (!!str). Found by the DF2 fuzz run at
	// input "!" (also "a: !", "- !"). Plain empty nodes (`a:`, `~`, `null`) decode
	// to null in BOTH, and an explicit `!!str` decodes to "" in BOTH — only the
	// bare non-specific `!` diverges. v4's behaviour is the more spec-aligned one
	// (the `!` non-specific tag forces resolution off the null default; the
	// failsafe schema resolves a `!`-tagged scalar as !!str). This is a deliberate
	// major-version correctness change, not a Keyorix defect: v4 has no live caller
	// today, so it is a forward-looking migration hazard (a config `key: !` would
	// flip from nil to "" on a v3→v4 bump). See EXPECTED-DIFFERENCES-yaml-v3-v4-
	// differential.md and the DF2 report. Enforced structurally by
	// classifyYAMLV4ValueSplit/nilVsEmptyStringOnly (null-vs-"" leaves only).
	"nonspecific-tag-empty-scalar": true,

	// The non-specific tag `!` applied to a NON-empty scalar. v3.0.5 ignores the
	// `!` and resolves the scalar by its normal implicit schema ("! 00" -> int 0,
	// "! true" -> bool true, "! null" -> nil, "! 1.5" -> float 1.5); v4.0.0 treats
	// `!` as forcing the failsafe !!str resolution and keeps the RAW STRING ("00",
	// "true", "null", "1.5"). "! abc" agrees (both "abc") because abc resolves to a
	// string in v3 anyway. This is the SAME root cause as nonspecific-tag-empty-
	// scalar (D1), generalised from the empty scalar to any non-empty one -- the
	// D1 classifier left out of DF2 (df2 leftover #1). The live caller
	// (gopkg.in/yaml.v3 v3.0.1) was verified to match go.yaml.in/yaml/v3 v3.0.5
	// byte-for-byte on every case here, so the reachable behaviour is the v3 side.
	// v4 has no live caller, so this is a forward-looking migration hazard: a
	// config `key: ! 00` would flip from int 0 to the string "00" on a v3->v4 bump.
	// Enforced structurally by classifyYAMLV4ValueSplit/nonspecificTagNonEmptyScalar
	// Only -- recognised ONLY when every differing leaf is "v4 kept the raw string s
	// and v3's value is exactly the v3 implicit resolution of s" AND the input
	// carries a non-specific `!` tag, so an unrelated value mismatch (e.g. v3 int 5
	// vs v4 string "6") still classes as value-mismatch and fails.
	"nonspecific-tag-nonempty-scalar": true,

	// The non-specific `!` tag re-resolution landing in a KEY position (`! : 00`,
	// `! 00: x`), where v3 and v4 produce DIFFERENT map keys (v3 nil/typed vs v4 raw
	// string) so the value-only walkers cannot pair the entries and fall through to
	// value-mismatch. Same root cause as D1/D12 (v4 honours `!` as `!!str`, v3 does
	// not), just at a key. Found by the DF3 struct fuzzer at `! : 00`. Recognised by
	// nonspecificTagEq, which pairs map entries across the tag transformation at any
	// position and requires every differing leaf to be "v4 string s, v3 = v3-resolve
	// (s)"; a genuine value diff (v3 5 vs v4 "6") is never equated. Scoped to inputs
	// carrying a `!` tag. v4 has no live caller — forward-looking migration hazard.
	"nonspecific-tag-structural": true,

	// A `:` inside an anchor NAME (`&a:b`, `&00:00000`, `k: &00:00000`). v3.0.5 ends
	// the anchor name at the `:` (so `&a:b` → anchor `a`, content ":b"); v4.0.0
	// absorbs the `:` into the name (anchor `a:b`, EMPTY node → nil). BOTH accept but
	// the decoded values differ. Found by the DF3 struct fuzzer at `&00:00000`. Same
	// anchor-name-character family as D9 (`&!0000`), but here both accept and
	// disagree on the value rather than v3 rejecting. Recognised CAUSALLY by
	// isAnchorColonBoundaryDivergence (stripping the anchor makes the two agree and
	// leaves v3's value unchanged), so a genuine divergence that merely contains an
	// anchor is never absorbed. v4 has no live caller — forward-looking.
	"anchor-name-colon-boundary": true,

	// The `-0` int-vs-float divergence (D10) in a KEY position (`-0:` → v3 key int 0
	// / v4 key float negative zero), where the maps do not align by key and the
	// value-only walker falls through to value-mismatch. Same root cause as D10, at a
	// key. Found by the DF3 multi-doc fuzzer at `-0:`. Recognised by negZeroEq
	// (pairs entries across the int-0/float-negzero transformation), scoped to inputs
	// containing `-0`. v4 has no live caller — forward-looking.
	"negative-zero-structural": true,

	// A truncated / unterminated construct — e.g. a block scalar followed by a lone
	// `"` at column 0 (`|\n"`), which v3 reads as an unterminated double-quoted
	// scalar. v3.0.5 REJECTS ("found unexpected end of stream"); v4.0.0 is lenient
	// and ACCEPTS. Found by the DF3 fuzz run at `|\n"`. v4 accepts what v3 rejects
	// (the migration-hazard direction, like D2/D3) but on malformed/truncated input.
	// Not a Keyorix defect (v4 has no live caller). Keyed on the v3 error "unexpected
	// end of stream".
	"v3-rejects:unexpected-eos": true,

	// A `%`-introduced directive v3 rejects — e.g. under-indented block-scalar
	// content `%0` (`|\n%0`) that v3 re-scans as a document directive ("found
	// unknown directive name"). v3.0.5 REJECTS; v4.0.0 ACCEPTS. Found by the DF3 fuzz
	// run at `|\n%0`. Same v4-lenient direction as D20. Not a Keyorix defect (v4 has
	// no live caller). Keyed on the v3 error substring "directive".
	"v3-rejects:directive": true,

	// The doc-start error in the v3-rejecting direction (the mirror of D4's
	// v4-rejects:doc-start). A folded/literal block scalar with under-indented
	// content in a STREAM decode (`>\n0`) makes v3's Decoder loop reject with "did
	// not find expected <document start>" while v4's Loader accepts it as one
	// document. Found by the DF3 multi-doc fuzzer at `>\n0`. v4 accepts what v3
	// rejects, benignly. Not a Keyorix defect (v4 has no live caller). Keyed on the
	// "expected <document start>" error with the v3-rejecting side.
	"v3-rejects:doc-start": true,

	// The `<<` merge-key indicator used where it is not a valid map-merge (`<<`,
	// `a: <<`, `- <<`, `k: <<`). v3.0.5 keeps the literal string "<<"; v4.0.0 treats
	// it as a merge directive and SILENTLY DROPS the entry/element (empty container
	// or nil) -- a v4 silent-data-loss footgun. Found by the DF3 struct fuzzer at
	// `<<`. Recognised causally by isMergeKeyDivergence (single-quoting every `<<`
	// makes the two agree and reproduces v3's value). Not a Keyorix defect (v4 has no
	// live caller); a forward-looking v4 data-loss note. Scoped to inputs containing
	// `<<`.
	"merge-key-handling": true,

	// A flow-mapping entry whose `:` is immediately followed by `}`/`,` with no space
	// (`{0:}`, `0: {0:}`): v3 keeps the `:` in the key (`"0:"`), v4 treats it as the
	// key/value separator (key `0`, null). Found by the DF3 fuzz run at `0: {0:}`.
	// Recognised causally by isFlowColonNoSpaceDivergence (adding a space after the
	// `:` makes v3 agree with v4, which is unchanged). Not a Keyorix defect (v4 has no
	// live caller). Scoped to inputs containing `:}`/`:,`.
	"flow-map-colon-nospace": true,

	// A `?` complex-key indicator in a context v3 forbids — e.g. `&0?` (anchor then
	// `?`). v3.0.5 REJECTS ("mapping keys are not allowed in this context"); v4.0.0
	// ACCEPTS leniently. Found by the DF3 multi-doc fuzzer at `&0?`. v4 accepts what
	// v3 rejects (migration-hazard direction). Not a Keyorix defect (v4 has no live
	// caller). Keyed on the v3 error "mapping keys are not allowed".
	"v3-rejects:mapping-key-context": true,

	// A mapping entry with an EMPTY implicit key -- a line beginning with the value
	// indicator `:` (":", ": ", ":\n", "- :", "a:\n:"). v3.0.5 REJECTS it ("did
	// not find expected key"); v4.0.0 ACCEPTS it, decoding to a null key -> null
	// value ({null: null}). Found by the DF2 fuzz run at input ":". Both readings
	// are defensible (YAML permits an empty/implicit key); v4 is the more permissive
	// one. This is the security-relevant DIRECTION (v4 accepts what v3 rejects): on a
	// v3->v4 migration a config line that is rejected today would silently parse as a
	// null-keyed mapping. Not a Keyorix defect today (v4 has no live caller); a
	// forward-looking migration/validation-parity hazard, documented in
	// EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md. Scoped tightly to the v3 error
	// "did not find expected key" so it does NOT tolerate any other v3 syntax
	// rejection the fuzzer may find.
	"v3-rejects:empty-implicit-key": true,

	// DEL (0x7F) and the C1 control range (0x80-0x9F, except NEL 0x85) in scalar
	// content. v3.0.5 REJECTS these ("control characters are not allowed"); v4.0.0
	// ACCEPTS them and keeps the control byte in the decoded string (confirmed both
	// as a bare document "\x7f" and embedded, "k: a\x7fb"). C0 controls (0x00-0x1F,
	// except tab/LF/CR) are rejected by BOTH; NEL (0x85) and NBSP (0xA0) are accepted
	// by BOTH. So the split is exactly DEL + C1. v3 is the STRICTER (safer) side here;
	// v4 relaxed the printable-character policy. Found by the DF2 fuzz run at "\x7f".
	// This is the security-relevant direction and the most migration-sensitive class:
	// on a v3->v4 bump, control characters (terminal escapes, DEL) that are rejected
	// today would pass into config string values. Not a Keyorix defect today (v4 has
	// no live caller); a forward-looking hazard AND an upstream HARDENING note about
	// v4's relaxed control-char validation. Keyed on the v3 error "control characters
	// are not allowed", so it does not tolerate any other rejection.
	"v3-rejects:control-char": true,

	// A plain scalar followed by a value indicator `:` at the START of the next
	// line ("0\n:", "a\n: b", "0\n: x"). v3.0.5 ACCEPTS it and keeps ONLY the
	// leading scalar (decoding "0\n:" to the int 0), SILENTLY dropping the second
	// line; v4.0.0 REJECTS the malformed document ("did not find expected
	// <document start>"). Here v4 is the STRICTER/safer side, and v3 exhibits silent
	// input truncation. Found by the DF2 fuzz run at "0\n:". The reachable library
	// (v3) is the lenient one, so this is an upstream-style observation about v3's
	// silent-drop behaviour on malformed multi-line scalars-vs-mapping input, not a
	// Keyorix defect (no code feeds such malformed YAML to a security decision).
	// Keyed on the v4 error "expected <document start>" alone.
	"v4-rejects:doc-start": true,

	// A flow indicator (`,` `[` `]`) inside a non-verbatim tag suffix ("!,", "!tag[",
	// "a: !,x", "x: !!str,"). v4.0.0 strictly REJECTS it ("found character '…' that
	// is not allowed in a YAML tag"); v3.0.5 is lenient — it ends the tag before the
	// flow char and treats the remainder as content (decoding to ""/the trailing
	// scalar). `!{`/`!}` are rejected by BOTH; a verbatim `!<a,b>` is accepted by
	// BOTH; only the non-verbatim flow-char suffix splits. v4 is the more
	// spec-correct side (flow indicators are not valid tag characters). Found by the
	// DF2 fuzz run at "0: !,". Not a Keyorix defect (v4 has no live caller); a
	// forward-looking strictness change. Keyed on the v4 error "not allowed in a YAML
	// tag" alone.
	"v4-rejects:tag-char": true,

	// A `#` comment NOT preceded by whitespace ("|#0", and similar). The YAML spec
	// requires a comment to be preceded by whitespace (or start of line); v4.0.0
	// enforces this and REJECTS ("found a comment without preceding whitespace"),
	// v3.0.5 is lenient and ACCEPTS. v4 is the more spec-correct side (same strictness
	// direction as D4/D5). Found by the DF2 fuzz run at "|#0". Not a Keyorix defect
	// (v4 has no live caller); a forward-looking strictness change. Keyed on the v4
	// error "comment without preceding whitespace" alone.
	"v4-rejects:comment-ws": true,

	// A leading character v3's scanner refuses to start any token with — notably a
	// bare TAB ("\t"). v3.0.5 REJECTS ("found character that cannot start any
	// token"); v4.0.0 ACCEPTS it as an empty document (nil). Other chars with the
	// same v3 error (`@`, backtick) are rejected by BOTH, so only the leading-TAB
	// case splits. v4 accepts what v3 rejects (benign — an empty/nil document).
	// Found by the DF2 fuzz run at "\t". Not a Keyorix defect (v4 has no live
	// caller). Keyed on the v3 error "cannot start any token" alone.
	"v3-rejects:token-start": true,

	// Under-indented block-scalar content. When a `|` or `>` block scalar is
	// followed by content at insufficient indentation (e.g. "|\n00", ">\nx",
	// "|-\n0\n1" — content at column 0), v3.0.5 decodes the scalar as the EMPTY
	// string, SILENTLY DROPPING the content; v4.0.0 captures it ("00", "x",
	// "0\n1"). Properly-indented block scalars ("|\n  00") agree in BOTH. This is a
	// value-level divergence in the SECURITY-RELEVANT, REACHABLE direction: the
	// library Keyorix tooling uses (v3) silently loses block-scalar content on a
	// mis-indented document. It is NOT a Keyorix defect today (no code feeds such
	// malformed YAML to a security decision) but it is a genuine v3 silent-data-loss
	// footgun worth reporting upstream. Recognised ONLY when every differing leaf is
	// v3-"" vs a non-empty v4 string AND the input carries a block-scalar header, so
	// no other value divergence is absorbed. Found by the DF2 fuzz run at "|\n00".
	"block-scalar-underindent": true,

	// An anchor/alias name containing a character v3 forbids there — e.g. "&!0000",
	// an anchor name with `!`. v3.0.5 REJECTS ("did not find expected alphabetic or
	// numeric character"); v4.0.0 is lenient and ACCEPTS. v4 accepts what v3 rejects
	// (benign — the anchor name does not affect the resolved value). Found by the DF2
	// fuzz run at "o: &!0000". Not a Keyorix defect (v4 has no live caller). Keyed on
	// the v3 anchor-char error alone.
	"v3-rejects:anchor-char": true,

	// The literal `-0`. v3.0.5 resolves it to int 0; v4.0.0 resolves it to float64
	// NEGATIVE ZERO (-0.0). Every other number tested (+0, -0.0, 0x0, 010, 1e3, …)
	// agrees in BOTH — only the bare `-0` splits. A genuine but tiny type/value
	// divergence (a config `-0` would be an int in v3, a float in v4). Found by the
	// DF2 fuzz run at "- -0". Not a Keyorix defect (v4 has no live caller). Recognised
	// only for int-0-vs-float-negzero leaves.
	"negative-zero-int-vs-float": true,

	// A tag/node in FLOW context lacking the whitespace v3 requires after it —
	// e.g. "{!}", a `!`-tagged empty node inside a flow mapping. v3.0.5 REJECTS
	// ("did not find expected whitespace or line break"); v4.0.0 is lenient and
	// ACCEPTS. v4 accepts what v3 rejects (benign flow-context leniency, same family
	// as D5/D9). Found by the DF2 fuzz run at "{!}". Not a Keyorix defect (v4 has no
	// live caller). Keyed on the v3 flow-ws error alone.
	"v3-rejects:flow-ws": true,

	// A tag (`!`, `!local`) on an EMPTY node inside a FLOW SEQUENCE ("[!x]", "[0:
	// !]", "[a: !x]", "[1: !]"). v3.0.5 REJECTS ("did not find expected ',' or ']'")
	// -- its flow scanner cannot handle a tag with no node content before the
	// separator; v4.0.0 ACCEPTS, resolving the tagged-empty node to "". A tag on a
	// NON-empty flow scalar ("[0: !t 1]") is accepted by BOTH, so only the
	// tagged-EMPTY-in-flow case splits. Found by the DF3 struct fuzzer at
	// "0: [0: !0000000]". Same v4-lenient flow family as D11 ("{!}"), different
	// container and error. v4 accepts what v3 rejects (the security-relevant
	// direction) but benignly (empty-string value). Not a Keyorix defect (v4 has no
	// live caller); a forward-looking flow-leniency migration note. Keyed on the v3
	// error substring "',' or ']'" alone.
	"v3-rejects:flow-seq-tagged-empty": true,

	// An EMPTY key/node in FLOW context ("[: 1]"). v3.0.5 REJECTS ("did not find
	// expected node content"); v4.0.0 ACCEPTS it as a null-keyed single-pair map
	// element. The flow-context analogue of D2 (block empty-implicit-key). Found by
	// the DF3 fuzz run. v4 accepts what v3 rejects (benign — a null key). Not a
	// Keyorix defect (v4 has no live caller); a forward-looking flow-leniency
	// migration note. Keyed on the v3 error "did not find expected node content".
	"v3-rejects:flow-node-content": true,
}

// TestYAMLV4DifferentialRedGreen is the committed red/green proof for the three
// oracles of FuzzYAMLV4Differential. Each oracle is shown to FIRE on a planted
// divergence (red) and NOT fire on a benign input (green). No production code is
// modified: every "defect" is expressible as fuzz INPUT or as a forced value, in
// the style of TestResguardBackupfmtDiskRedGreen.
func TestYAMLV4DifferentialRedGreen(t *testing.T) {
	budget := calibrateYAMLV4(t)

	// ---- Oracle 1: bounded work ----
	// GREEN: a benign document passes the calibrated budget.
	{
		data := []byte("x: 1\na:\n  b:\n    c: 1\n")
		p := resguard.New(t, resguard.Options{SampleEvery: 1})
		var v any
		c := p.Measure(len(data), func() { _ = v3yaml.Unmarshal(data, &v) })
		if budget.Check(func(string, ...any) {}, c) {
			t.Fatalf("GREEN failed: benign doc tripped bounded-work budget (alloc=%d for %d bytes)", c.AllocBytes, len(data))
		}
	}
	// RED: a single anchor referenced many times at one level stays UNDER the
	// excessive-aliasing cap (so Unmarshal ACCEPTS it) yet materialises N copies
	// of the referenced sequence — super-linear alloc for a small input. This is
	// the memory-amplification shape the bounded-work oracle exists to catch; it
	// is attacker INPUT, so no production code is touched.
	{
		data := yamlAmplifierInput()
		p := resguard.New(t, resguard.Options{SampleEvery: 1})
		var v any
		var uerr error
		c := p.Measure(len(data), func() { uerr = v3yaml.Unmarshal(data, &v) })
		if uerr != nil {
			t.Fatalf("RED precondition: the amplifier input must be ACCEPTED (else it is a reject, not an amplification): %v", uerr)
		}
		if c.AllocBytes < 1<<20 {
			t.Fatalf("RED precondition: amplifier must allocate >=1 MiB for a ~%d-byte input, got %d", len(data), c.AllocBytes)
		}
		var fired bool
		budget.Check(func(string, ...any) { fired = true }, c)
		if !fired {
			t.Fatalf("RED failed: amplifier (alloc=%d for %d-byte input) did NOT trip the bounded-work budget", c.AllocBytes, len(data))
		}
		t.Logf("oracle-1 RED fired: amplifier input %d bytes -> alloc %d bytes", len(data), c.AllocBytes)
	}

	// ---- Oracle 2: accept/reject parity, gated by the table ----
	// RED: a split verdict whose class is absent from the (empty) table fires.
	{
		err3 := error(nil)
		err4 := &yamlErr{"yaml: construct errors: line 2: mapping key \"x\" already defined"}
		class := classifyYAMLV4Split(err3, err4)
		if yamlV4ExpectedDiff[class] {
			t.Fatalf("RED precondition: class %q must NOT be in the table for this proof", class)
		}
		// With the class absent, the fuzz body would t.Fatalf — that is the fire.
		// GREEN: the same split is silenced once the class is listed.
		tolerated := map[string]bool{class: true}
		if !tolerated[class] {
			t.Fatalf("GREEN failed: listing class %q did not silence the split", class)
		}
		t.Logf("oracle-2 RED fired on class %q; GREEN silences it when listed", class)
	}

	// ---- Oracle 3: decoded-value equality via one canonical encoder ----
	// RED: two decoded values that genuinely differ produce different canonical
	// bytes, so the oracle fires. GREEN: equal values (incl. NaN) canonicalise
	// identically, so it does not — proving the NaN!=NaN DeepEqual trap is avoided.
	{
		a := map[string]any{"k": 1}
		b := map[string]any{"k": 2}
		ca, _ := v3yaml.Marshal(a)
		cb, _ := v3yaml.Marshal(b)
		if string(ca) == string(cb) {
			t.Fatalf("RED failed: differing values produced identical canonical bytes")
		}
		// GREEN: NaN round-trips to the same canonical string from both libraries.
		nanDoc := []byte("n: .nan\n")
		var v3v, v4v any
		if err := v3yaml.Unmarshal(nanDoc, &v3v); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(nanDoc, &v4v); err != nil {
			t.Fatal(err)
		}
		cn3, _ := v3yaml.Marshal(v3v)
		cn4, _ := v3yaml.Marshal(v4v)
		if string(cn3) != string(cn4) {
			t.Fatalf("GREEN failed: NaN canonicalised differently across libs: v3=%q v4=%q (DeepEqual NaN trap not avoided)", cn3, cn4)
		}
		t.Logf("oracle-3 RED fires on value diff; GREEN: NaN canonicalises identically (%q)", cn3)
	}

	// ---- Oracle 3 class gating: the non-specific-tag divergence ----
	// This is the one real divergence the DF2 fuzz run found. Prove (a) it is
	// classified as the tolerated class and would be silenced, and (b) the
	// classifier does NOT over-tolerate — an unrelated value diff still classes as
	// "value-mismatch" (absent from the table → fails).
	{
		// The actual decoded shapes for "a: !": v3 -> {"a": nil}, v4 -> {"a": ""}.
		v3shape := map[string]any{"a": nil}
		v4shape := map[string]any{"a": ""}
		class := classifyYAMLV4ValueSplit([]byte("a: !"), v3shape, v4shape)
		if class != "nonspecific-tag-empty-scalar" {
			t.Fatalf("expected the `!`-empty divergence to class as nonspecific-tag-empty-scalar, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("the nonspecific-tag class must be listed (tolerated) in the table")
		}
		// RED: an unrelated value diff must NOT be absorbed by the class.
		other := classifyYAMLV4ValueSplit([]byte("a: 1"), map[string]any{"a": 1}, map[string]any{"a": 2})
		if other != "value-mismatch" {
			t.Fatalf("an unrelated int divergence must class as value-mismatch, got %q", other)
		}
		if yamlV4ExpectedDiff[other] {
			t.Fatalf("value-mismatch must NOT be tolerated (else the oracle is blind)")
		}
		// A nil-vs-NON-empty-string diff must also fall through (not the `!` class).
		nonEmpty := classifyYAMLV4ValueSplit([]byte("a: x"), map[string]any{"a": nil}, map[string]any{"a": "x"})
		if nonEmpty != "value-mismatch" {
			t.Fatalf("nil-vs-non-empty-string must class as value-mismatch, got %q", nonEmpty)
		}
		// The int-key case ("0: !") decodes into map[any]any, which the classifier
		// must still recognise (found by the fuzzer at "0: ! ").
		intKey := classifyYAMLV4ValueSplit([]byte("0: !"), map[any]any{0: nil}, map[any]any{0: ""})
		if intKey != "nonspecific-tag-empty-scalar" {
			t.Fatalf("the int-key `!`-empty case must class as nonspecific-tag-empty-scalar, got %q", intKey)
		}
		t.Logf("oracle-3 class gating proven: `!`-empty tolerated; int/non-empty diffs still fail")
	}

	// ---- Oracle 2 class gating: the empty-implicit-key divergence ----
	// Prove the real v3-rejects/v4-accepts split for ":" classifies to the tolerated
	// empty-implicit-key class, and that an UNRELATED v3 syntax rejection does NOT
	// get absorbed by it (it stays :syntax, absent from the table -> fails).
	{
		var v3v, v4v any
		err3 := v3yaml.Unmarshal([]byte(":"), &v3v)
		err4 := v4yaml.Unmarshal([]byte(":"), &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: ':' must be rejected by v3 and accepted by v4 (v3err=%v v4err=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:empty-implicit-key" {
			t.Fatalf("':' split must class as v3-rejects:empty-implicit-key, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("empty-implicit-key class must be listed (tolerated)")
		}
		// RED: a DIFFERENT v3 syntax rejection must not be silenced by this class and
		// must stay the untolerated generic :syntax (use a directive error, which is
		// not one of the specifically-classed flow/tag/key messages).
		other := classifyYAMLV4Split(&yamlErr{"yaml: did not find expected '-' indicator"}, nil)
		if other == "v3-rejects:empty-implicit-key" {
			t.Fatalf("an unrelated v3 syntax rejection was wrongly absorbed into empty-implicit-key")
		}
		if other != "v3-rejects:syntax" || yamlV4ExpectedDiff[other] {
			t.Fatalf("the generic syntax split (%q) must NOT be tolerated", other)
		}
		t.Logf("oracle-2 empty-implicit-key gating proven: ':' tolerated; other syntax splits still fail (%q)", other)
	}

	// ---- Oracle 2 class gating: the control-char divergence ----
	// DEL (0x7F) is rejected by v3, accepted by v4; prove it classes as the tolerated
	// control-char class, and that a C0 control (rejected by BOTH) never produces a
	// split to tolerate in the first place.
	{
		del := []byte{0x7f}
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(del, &v3v)
		err4 := v4yaml.Unmarshal(del, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: DEL must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:control-char" {
			t.Fatalf("DEL split must class as v3-rejects:control-char, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("control-char class must be listed (tolerated)")
		}
		// A C0 control (0x00) is rejected by BOTH -> no split, so the oracle never
		// reaches the table; confirm the shared-reject precondition holds.
		var z1, z2 any
		if v3yaml.Unmarshal([]byte{0x00}, &z1) == nil || v4yaml.Unmarshal([]byte{0x00}, &z2) == nil {
			t.Fatalf("precondition: a C0 NUL must be rejected by BOTH libraries")
		}
		t.Logf("oracle-2 control-char gating proven: DEL/C1 tolerated; C0 rejected by both")
	}

	// ---- Oracle 2 class gating: the doc-start divergence (v4 stricter) ----
	{
		in := []byte("0\n:")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 != nil || err4 == nil {
			t.Fatalf("precondition: '0\\n:' must be accepted by v3 and rejected by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v4-rejects:doc-start" {
			t.Fatalf("doc-start split must class as v4-rejects:doc-start, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("doc-start class must be listed (tolerated)")
		}
		// Document the silent-truncation observation: v3 kept ONLY the leading scalar.
		if v3v != 0 {
			t.Fatalf("expected v3 to keep only the leading scalar 0 (silent drop), got %#v", v3v)
		}
		t.Logf("oracle-2 doc-start gating proven: v3 accepts+truncates to %#v, v4 rejects", v3v)
	}

	// ---- Oracle 2 class gating: the tag-char divergence (v4 stricter) ----
	{
		in := []byte("!,")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 != nil || err4 == nil {
			t.Fatalf("precondition: '!,' must be accepted by v3 and rejected by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v4-rejects:tag-char" {
			t.Fatalf("tag-char split must class as v4-rejects:tag-char, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("tag-char class must be listed (tolerated)")
		}
		// A verbatim tag with the same chars is accepted by BOTH (no split).
		var w1, w2 any
		if v3yaml.Unmarshal([]byte("!<a,b>"), &w1) != nil || v4yaml.Unmarshal([]byte("!<a,b>"), &w2) != nil {
			t.Fatalf("precondition: verbatim tag !<a,b> must be accepted by BOTH")
		}
		t.Logf("oracle-2 tag-char gating proven: non-verbatim flow-char tag tolerated; verbatim accepted by both")
	}

	// ---- Oracle 2 class gating: the comment-whitespace divergence (v4 stricter) ----
	{
		in := []byte("|#0")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 != nil || err4 == nil {
			t.Fatalf("precondition: '|#0' must be accepted by v3 and rejected by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v4-rejects:comment-ws" {
			t.Fatalf("comment-ws split must class as v4-rejects:comment-ws, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("comment-ws class must be listed (tolerated)")
		}
		t.Logf("oracle-2 comment-ws gating proven")
	}

	// ---- Oracle 2 class gating: the leading-TAB token-start divergence ----
	{
		var v3v, v4v any
		err3 := v3yaml.Unmarshal([]byte("\t"), &v3v)
		err4 := v4yaml.Unmarshal([]byte("\t"), &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: leading TAB must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:token-start" {
			t.Fatalf("leading-TAB split must class as v3-rejects:token-start, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("token-start class must be listed (tolerated)")
		}
		t.Logf("oracle-2 token-start gating proven")
	}

	// ---- Oracle 3 class gating: block-scalar under-indentation (v3 data loss) ----
	{
		in := []byte("|\n00")
		var v3v, v4v any
		if err := v3yaml.Unmarshal(in, &v3v); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(in, &v4v); err != nil {
			t.Fatal(err)
		}
		if v3v != "" || v4v != "00" {
			t.Fatalf("precondition: '|\\n00' must decode to \"\" in v3 and \"00\" in v4; got v3=%#v v4=%#v", v3v, v4v)
		}
		class := classifyYAMLV4ValueSplit(in, v3v, v4v)
		if class != "block-scalar-underindent" {
			t.Fatalf("block-scalar divergence must class as block-scalar-underindent, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("block-scalar-underindent must be listed (tolerated)")
		}
		// RED: the SAME empty-vs-nonempty shape WITHOUT a block-scalar header must
		// NOT be absorbed (stays value-mismatch -> fails).
		noHeader := classifyYAMLV4ValueSplit([]byte("a: b"), map[string]any{"a": ""}, map[string]any{"a": "x"})
		if noHeader != "value-mismatch" {
			t.Fatalf("empty-vs-nonempty WITHOUT a block header must stay value-mismatch, got %q", noHeader)
		}
		t.Logf("oracle-3 block-scalar gating proven: v3 drops to \"\", v4 keeps \"00\"; non-block empty-vs-nonempty still fails")
	}

	// ---- Oracle 2 class gating: anchor-name character leniency ----
	{
		in := []byte("o: &!0000")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: '&!0000' anchor must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:anchor-char" {
			t.Fatalf("anchor-char split must class as v3-rejects:anchor-char, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("anchor-char class must be listed (tolerated)")
		}
		t.Logf("oracle-2 anchor-char gating proven")
	}

	// ---- Oracle 3 class gating: -0 int-vs-float ----
	{
		in := []byte("- -0")
		var v3v, v4v any
		if err := v3yaml.Unmarshal(in, &v3v); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(in, &v4v); err != nil {
			t.Fatal(err)
		}
		class := classifyYAMLV4ValueSplit(in, v3v, v4v)
		if class != "negative-zero-int-vs-float" {
			t.Fatalf("'-0' divergence must class as negative-zero-int-vs-float, got %q (v3=%#v v4=%#v)", class, v3v, v4v)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("negative-zero class must be listed (tolerated)")
		}
		// RED: an int-vs-float diff that is NOT negative zero must stay value-mismatch.
		notNegZero := classifyYAMLV4ValueSplit([]byte("x: 1"), map[string]any{"x": 1}, map[string]any{"x": float64(1)})
		if notNegZero != "value-mismatch" {
			t.Fatalf("a non-negzero int-vs-float diff must stay value-mismatch, got %q", notNegZero)
		}
		t.Logf("oracle-3 negative-zero gating proven")
	}

	// ---- Oracle 3 class gating: non-specific `!` tag on a NON-empty scalar (D12) ----
	// The DF2 leftover #1: generalise D1 from the empty scalar to a non-empty one.
	{
		for _, tc := range []struct {
			in     string
			wantV3 any
			wantV4 any
		}{
			{"! 00", 0, "00"},
			{"! true", true, "true"},
			{"! null", nil, "null"},
			{"! 1.5", 1.5, "1.5"},
		} {
			var v3v, v4v any
			if err := v3yaml.Unmarshal([]byte(tc.in), &v3v); err != nil {
				t.Fatalf("%q: v3 unmarshal: %v", tc.in, err)
			}
			if err := v4yaml.Unmarshal([]byte(tc.in), &v4v); err != nil {
				t.Fatalf("%q: v4 unmarshal: %v", tc.in, err)
			}
			if !reflect.DeepEqual(v3v, tc.wantV3) || !reflect.DeepEqual(v4v, tc.wantV4) {
				t.Fatalf("precondition %q: want v3=%#v v4=%#v, got v3=%#v v4=%#v", tc.in, tc.wantV3, tc.wantV4, v3v, v4v)
			}
			class := classifyYAMLV4ValueSplit([]byte(tc.in), v3v, v4v)
			if class != "nonspecific-tag-nonempty-scalar" {
				t.Fatalf("%q: want class nonspecific-tag-nonempty-scalar, got %q", tc.in, class)
			}
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("nonspecific-tag-nonempty-scalar must be listed (tolerated)")
			}
		}
		// RED #1: a genuine int-vs-string mismatch where the string does NOT resolve
		// (in v3) to the int must stay value-mismatch (v3 int 5 vs v4 string "6").
		bad := classifyYAMLV4ValueSplit([]byte("x: ! 5"), map[string]any{"x": 5}, map[string]any{"x": "6"})
		if bad != "value-mismatch" {
			t.Fatalf("a non-resolving int-vs-string diff must stay value-mismatch, got %q", bad)
		}
		// RED #2: the exact D12 shape but WITHOUT a non-specific `!` tag in the input
		// must NOT be absorbed (scoping gate) -- stays value-mismatch.
		noTag := classifyYAMLV4ValueSplit([]byte("x: 00"), map[string]any{"x": 0}, map[string]any{"x": "00"})
		if noTag != "value-mismatch" {
			t.Fatalf("the D12 value shape WITHOUT a `!` tag must stay value-mismatch, got %q", noTag)
		}
		// GREEN scoping: the same shape WITH a `!` tag is tolerated.
		withTag := classifyYAMLV4ValueSplit([]byte("x: ! 00"), map[string]any{"x": 0}, map[string]any{"x": "00"})
		if withTag != "nonspecific-tag-nonempty-scalar" {
			t.Fatalf("the D12 shape WITH a `!` tag must be tolerated, got %q", withTag)
		}
		// The empty-scalar D1 case must still class as the ORIGINAL class, not D12.
		empty := classifyYAMLV4ValueSplit([]byte("x: !"), map[string]any{"x": nil}, map[string]any{"x": ""})
		if empty != "nonspecific-tag-empty-scalar" {
			t.Fatalf("the empty `!` case must stay nonspecific-tag-empty-scalar, got %q", empty)
		}
		t.Logf("oracle-3 D12 gating proven: `! <scalar>` tolerated; non-resolving/untagged diffs still fail; D1 unchanged")
	}

	// ---- Oracle 3 class gating: nonspecific-tag in a KEY position (D17 structural) ----
	{
		for _, in := range []string{"! : 00", "! 00 : x"} {
			var v3v, v4v any
			if err := v3yaml.Unmarshal([]byte(in), &v3v); err != nil {
				t.Fatalf("%q: v3 unmarshal: %v", in, err)
			}
			if err := v4yaml.Unmarshal([]byte(in), &v4v); err != nil {
				t.Fatalf("%q: v4 unmarshal: %v", in, err)
			}
			class := classifyYAMLV4ValueSplit([]byte(in), v3v, v4v)
			if class != "nonspecific-tag-structural" {
				t.Fatalf("%q: want class nonspecific-tag-structural, got %q (v3=%#v v4=%#v)", in, class, v3v, v4v)
			}
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("nonspecific-tag-structural must be tolerated")
			}
		}
		// RED: a genuine key-set divergence must NOT be absorbed by nonspecificTagEq.
		if nonspecificTagEq(map[string]any{"a": 1}, map[string]any{"b": 1}) {
			t.Fatalf("different keys (a vs b, neither a tag reparse) must NOT be equated")
		}
		// RED: a value diff that is not a tag reparse must NOT be equated.
		if nonspecificTagEq(map[string]any{"a": 5}, map[string]any{"a": "6"}) {
			t.Fatalf("v3 5 vs v4 \"6\" (reparse 6 != 5) must NOT be equated")
		}
		// RED: the structural class must NOT fire without a `!` tag in the input.
		noTag := classifyYAMLV4ValueSplit([]byte("a: 1"), map[any]any{nil: 0}, map[string]any{"": "00"})
		if noTag == "nonspecific-tag-structural" {
			t.Fatalf("the structural class must require a `!` tag in the input, got %q", noTag)
		}
		t.Logf("oracle-3 D17 structural gating proven: `!`-tag KEY divergence tolerated; genuine key/value diffs and untagged inputs still fail")
	}

	// ---- Oracle 3 class gating: flow-map colon-no-space (D23) ----
	{
		in := []byte("0: {0:} ")
		var v3v, v4v any
		if err := v3yaml.Unmarshal(in, &v3v); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(in, &v4v); err != nil {
			t.Fatal(err)
		}
		cb3, _ := v3yaml.Marshal(v3v)
		cb4, _ := v3yaml.Marshal(v4v)
		if reflect.DeepEqual(cb3, cb4) {
			t.Fatalf("precondition: `0: {0:}` v3/v4 must disagree (v3=%q v4=%q)", cb3, cb4)
		}
		if class := classifyYAMLV4ValueSplit(in, v3v, v4v); class != "flow-map-colon-nospace" || !yamlV4ExpectedDiff[class] {
			t.Fatalf("`0: {0:}` must class as the tolerated flow-map-colon-nospace, got %q", class)
		}
		// RED: an input without a flow colon-no-space must not be recognised.
		if isFlowColonNoSpaceDivergence([]byte("a: 1"), map[string]any{"a": 1}, map[string]any{"a": 2}) {
			t.Fatalf("an input without `:}`/`:,` must not be recognised as flow-map-colon-nospace")
		}
		t.Logf("oracle-3 D23 flow-map-colon gating proven")
	}

	// ---- Oracle 3 class gating: `<<` merge-key handling (D22) ----
	{
		for _, in := range []string{"a: <<", "- <<", "k: <<"} {
			var v3v, v4v any
			if err := v3yaml.Unmarshal([]byte(in), &v3v); err != nil {
				t.Fatalf("%q: v3 unmarshal: %v", in, err)
			}
			if err := v4yaml.Unmarshal([]byte(in), &v4v); err != nil {
				t.Fatalf("%q: v4 unmarshal: %v", in, err)
			}
			cb3, _ := v3yaml.Marshal(v3v)
			cb4, _ := v3yaml.Marshal(v4v)
			if reflect.DeepEqual(cb3, cb4) {
				t.Fatalf("precondition %q: v3/v4 must disagree (v3=%q v4=%q)", in, cb3, cb4)
			}
			class := classifyYAMLV4ValueSplit([]byte(in), v3v, v4v)
			if class != "merge-key-handling" {
				t.Fatalf("%q: want class merge-key-handling, got %q (v3=%#v v4=%#v)", in, class, v3v, v4v)
			}
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("merge-key-handling must be tolerated")
			}
		}
		// RED: a genuine divergence that merely contains `<<` inside a quoted string
		// (so quoting does not change anything causal) must NOT be absorbed.
		if isMergeKeyDivergence([]byte("x: 1"), map[string]any{"x": 1}) {
			t.Fatalf("an input without a bare `<<` must not be recognised as merge-key")
		}
		t.Logf("oracle-3 D22 merge-key gating proven: `<<` drop tolerated causally; non-merge inputs still fail")
	}

	// ---- Oracle 2 class gating: v3 rejects a directive (D21) ----
	{
		in := []byte("|\n%0")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: `|\\n%%0` must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		if class := classifyYAMLV4Split(err3, err4); class != "v3-rejects:directive" || !yamlV4ExpectedDiff[class] {
			t.Fatalf("`|\\n%%0` split must class as the tolerated v3-rejects:directive, got %q", class)
		}
		t.Logf("oracle-2 directive gating proven")
	}

	// ---- Oracle 2 class gating: truncated construct, v3 rejects EOS (D20) ----
	{
		in := []byte("|\n\"")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: `|\\n\"` must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:unexpected-eos" {
			t.Fatalf("`|\\n\"` split must class as v3-rejects:unexpected-eos, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("unexpected-eos class must be tolerated")
		}
		t.Logf("oracle-2 unexpected-eos gating proven")
	}

	// ---- Oracle 3 class gating: -0 in a KEY position (D19 structural) ----
	{
		in := []byte("-0:")
		var v3v, v4v any
		if err := v3yaml.Unmarshal(in, &v3v); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(in, &v4v); err != nil {
			t.Fatal(err)
		}
		cb3, _ := v3yaml.Marshal(v3v)
		cb4, _ := v3yaml.Marshal(v4v)
		if reflect.DeepEqual(cb3, cb4) {
			t.Fatalf("precondition: `-0:` v3/v4 must disagree (v3=%q v4=%q)", cb3, cb4)
		}
		class := classifyYAMLV4ValueSplit(in, v3v, v4v)
		if class != "negative-zero-structural" {
			t.Fatalf("`-0:` must class as negative-zero-structural, got %q (v3=%#v v4=%#v)", class, v3v, v4v)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("negative-zero-structural must be tolerated")
		}
		// RED: a non-negzero key diff must NOT be absorbed; and without `-0` in input.
		if negZeroEq(map[any]any{1: nil}, map[any]any{2: nil}) {
			t.Fatalf("a genuine key diff (1 vs 2) must not be equated by negZeroEq")
		}
		notNeg := classifyYAMLV4ValueSplit([]byte("x: 1"), map[string]any{"x": 1}, map[string]any{"x": float64(1)})
		if notNeg == "negative-zero-structural" {
			t.Fatalf("a non-negzero int-vs-float diff must not class as negative-zero-structural, got %q", notNeg)
		}
		t.Logf("oracle-3 D19 negzero-structural gating proven: `-0:` key tolerated; genuine diffs still fail")
	}

	// ---- Oracle 3 class gating: colon inside an anchor name (D18) ----
	{
		for _, in := range []string{"&a:b", "&00:00000", "k: &00:00000"} {
			var v3v, v4v any
			if err := v3yaml.Unmarshal([]byte(in), &v3v); err != nil {
				t.Fatalf("%q: v3 unmarshal: %v", in, err)
			}
			if err := v4yaml.Unmarshal([]byte(in), &v4v); err != nil {
				t.Fatalf("%q: v4 unmarshal: %v", in, err)
			}
			cb3, _ := v3yaml.Marshal(v3v)
			cb4, _ := v3yaml.Marshal(v4v)
			if reflect.DeepEqual(cb3, cb4) {
				t.Fatalf("precondition %q: v3 and v4 must DISAGREE (v3=%q v4=%q)", in, cb3, cb4)
			}
			class := classifyYAMLV4ValueSplit([]byte(in), v3v, v4v)
			if class != "anchor-name-colon-boundary" {
				t.Fatalf("%q: want class anchor-name-colon-boundary, got %q (v3=%#v v4=%#v)", in, class, v3v, v4v)
			}
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("anchor-name-colon-boundary must be tolerated")
			}
		}
		// RED: a genuine divergence that merely CONTAINS an anchor (no colon-in-name
		// cause) must NOT be absorbed. `&a 1` vs a forced different value: stripping
		// `&a` does not make them agree.
		if isAnchorColonBoundaryDivergence([]byte("x: &a 1"), map[string]any{"x": 1}, map[string]any{"x": 2}) {
			t.Fatalf("a genuine value diff that merely contains an anchor must NOT be recognised")
		}
		// RED: an input with no anchor cannot be this class.
		if isAnchorColonBoundaryDivergence([]byte("a: 1"), map[string]any{"a": 1}, map[string]any{"a": 2}) {
			t.Fatalf("an input with no anchor must not be recognised as anchor-colon")
		}
		t.Logf("oracle-3 D18 anchor-colon gating proven: `&a:b`-style tolerated causally; genuine/anchorless diffs still fail")
	}

	// ---- Oracle 2 class gating: flow-context whitespace leniency ----
	{
		in := []byte("{!}")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: '{!}' must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:flow-ws" {
			t.Fatalf("flow-ws split must class as v3-rejects:flow-ws, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("flow-ws class must be listed (tolerated)")
		}
		t.Logf("oracle-2 flow-ws gating proven")
	}

	// ---- Oracle 2 class gating: tagged-empty node in a flow sequence (D15) ----
	{
		for _, in := range []string{"[!x]", "[0: !]", "[a: !x]", "[1: !]"} {
			var v3v, v4v any
			err3 := v3yaml.Unmarshal([]byte(in), &v3v)
			err4 := v4yaml.Unmarshal([]byte(in), &v4v)
			if err3 == nil || err4 != nil {
				t.Fatalf("precondition %q: must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", in, err3, err4)
			}
			class := classifyYAMLV4Split(err3, err4)
			if class != "v3-rejects:flow-seq-tagged-empty" {
				t.Fatalf("%q split must class as v3-rejects:flow-seq-tagged-empty, got %q", in, class)
			}
			if !yamlV4ExpectedDiff[class] {
				t.Fatalf("flow-seq-tagged-empty class must be listed (tolerated)")
			}
		}
		// A tag on a NON-empty flow scalar is accepted by BOTH (no split).
		var w1, w2 any
		if v3yaml.Unmarshal([]byte("[0: !t 1]"), &w1) != nil || v4yaml.Unmarshal([]byte("[0: !t 1]"), &w2) != nil {
			t.Fatalf("precondition: a tag on a NON-empty flow scalar must be accepted by BOTH")
		}
		t.Logf("oracle-2 flow-seq-tagged-empty gating proven: tagged-EMPTY-in-flow tolerated; tag-on-non-empty agrees")
	}

	// ---- Oracle 2 class gating: empty key in a flow sequence (D16) ----
	{
		in := []byte("[: 1]")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: '[: 1]' must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:flow-node-content" {
			t.Fatalf("'[: 1]' split must class as v3-rejects:flow-node-content, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("flow-node-content class must be listed (tolerated)")
		}
		// RED: a generic v3 syntax rejection must still fall through to :syntax (untolerated).
		other := classifyYAMLV4Split(&yamlErr{"yaml: did not find expected directive"}, nil)
		if other != "v3-rejects:syntax" || yamlV4ExpectedDiff[other] {
			t.Fatalf("a generic v3 syntax error must stay the untolerated :syntax class, got %q", other)
		}
		t.Logf("oracle-2 flow-node-content gating proven: '[: 1]' tolerated; generic syntax still fails")
	}
}

// yamlAmplifierInput builds an accepted-but-amplifying YAML document: one anchored
// sequence of scalars, referenced many times inside an outer sequence. The alias
// count stays under go.yaml's excessive-aliasing budget (so Unmarshal accepts)
// while each reference materialises a fresh copy of the inner sequence.
func yamlAmplifierInput() []byte {
	var sb strings.Builder
	// A modest inner payload...
	sb.WriteString("base: &b [")
	for i := range 60 {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("item")
	}
	sb.WriteString("]\n")
	// ...referenced many times in a flat list (no nesting -> under the cap).
	sb.WriteString("fan:\n")
	for range 900 {
		sb.WriteString("  - *b\n")
	}
	return []byte(sb.String())
}

// yamlErr is a minimal error carrying a fixed message for the oracle-2 proof.
type yamlErr struct{ s string }

func (e *yamlErr) Error() string { return e.s }
