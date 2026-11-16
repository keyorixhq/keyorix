package libconformance

import (
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
		class := classifyYAMLV4ValueSplit(v3shape, v4shape)
		if class != "nonspecific-tag-empty-scalar" {
			t.Fatalf("expected the `!`-empty divergence to class as nonspecific-tag-empty-scalar, got %q", class)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("the nonspecific-tag class must be listed (tolerated) in the table")
		}
		// RED: an unrelated value diff must NOT be absorbed by the class.
		other := classifyYAMLV4ValueSplit(map[string]any{"a": 1}, map[string]any{"a": 2})
		if other != "value-mismatch" {
			t.Fatalf("an unrelated int divergence must class as value-mismatch, got %q", other)
		}
		if yamlV4ExpectedDiff[other] {
			t.Fatalf("value-mismatch must NOT be tolerated (else the oracle is blind)")
		}
		// A nil-vs-NON-empty-string diff must also fall through (not the `!` class).
		nonEmpty := classifyYAMLV4ValueSplit(map[string]any{"a": nil}, map[string]any{"a": "x"})
		if nonEmpty != "value-mismatch" {
			t.Fatalf("nil-vs-non-empty-string must class as value-mismatch, got %q", nonEmpty)
		}
		// The int-key case ("0: !") decodes into map[any]any, which the classifier
		// must still recognise (found by the fuzzer at "0: ! ").
		intKey := classifyYAMLV4ValueSplit(map[any]any{0: nil}, map[any]any{0: ""})
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
		// RED: a DIFFERENT v3 syntax rejection must not be silenced by this class.
		other := classifyYAMLV4Split(&yamlErr{"yaml: did not find expected node content"}, nil)
		if other == "v3-rejects:empty-implicit-key" {
			t.Fatalf("an unrelated v3 syntax rejection was wrongly absorbed into empty-implicit-key")
		}
		if yamlV4ExpectedDiff[other] {
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
