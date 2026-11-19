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

	// D24. A flow-SEQUENCE entry whose `:` is immediately followed by `]` with no
	// space (`[0:]`, `[a:]`). v3.0.5 keeps the `:` IN the value (value `"0:"`), giving
	// a one-element sequence of a string; v4.0.0 treats the `:` as the key/value
	// separator (key `0`/`a`, null value), giving a one-element sequence of a {key:
	// null} map. The flow-SEQUENCE analogue of D23 (`{0:}` / `flow-map-colon-nospace`);
	// same root cause: a `:` without following whitespace inside a flow container. Found
	// by the DF3 fuzz run at `[0:]` (testdata/fuzz/FuzzYAMLV4Differential/28731c901e37d1c2).
	// Recognised causally by isFlowSeqColonNoSpaceDivergence (inserting `: ]` makes v3
	// agree with v4, which is unchanged). Not a Keyorix defect (v4 has no live caller).
	// Scoped to inputs containing `:]`.
	"flow-seq-colon-nospace": true,

	// D25. A mapping entry whose v4-side errors with "did not find expected key" while
	// v3 accepts — the INVERSE direction of D2 (v3-rejects:empty-implicit-key). Found
	// by the DF3 struct fuzzer at `0: &0:0000000,` (FuzzYAMLV4StructDifferential/
	// 05ca5f53b4ce7568). Root cause: D18 (anchor-colon absorption) makes v4 expand
	// `&0:0000000` to anchor name `0:0000000`, leaving `,` as the residual content in
	// a block mapping context; v4 then cannot find a key for the `,` entry and rejects.
	// v3 ends the anchor name at the first `:`, so `&0` is the anchor name and
	// `:0000000,` is a valid (if odd) mapping entry. v4 is the STRICTER side here;
	// the reachable library (v3) accepts the input. Not a Keyorix defect (v4 has no
	// live caller). Keyed on the v4 error "did not find expected key" with side
	// "v4-rejects", scoped away from D2's "v3-rejects" direction.
	"v4-rejects:empty-implicit-key": true,

	// D26. A block scalar with an explicit indentation indicator of 0 (`>0`, `|0`).
	// YAML spec §8.1 states the indentation indicator must be 1–9 if present; zero is
	// explicitly forbidden. v3.0.5 enforces this and REJECTS ("found an indentation
	// indicator equal to 0"); v4.0.0 is lenient and ACCEPTS. Found by the DF3 multi-doc
	// fuzzer at `>\n>0` (the SECOND document of the stream, testdata/fuzz/
	// FuzzYAMLV4MultiDocDifferential/9a8b08fc667ea076). v3 is the stricter/safer side.
	// Not a Keyorix defect (v4 has no live caller). Keyed on the v3 error substring
	// "found an indentation indicator equal to 0".
	"v3-rejects:indentation-indicator": true,

	// D27. Block-scalar end-of-stream clip difference. When a block scalar's last
	// content line is whitespace-only (above indent level) and the input ends without
	// a terminal newline, v3.0.5 omits the clip-chomping newline while v4.0.0 adds it.
	// Found by the DF3 fuzz run at `|\n 000000\n  ` (testdata/fuzz/
	// FuzzYAMLV4Differential/597ac6ec0bae9ae4). The shape is v4val == v3val + "\n" for
	// every differing string leaf. Confirmed causal: adding a trailing newline to the
	// input makes both parsers agree. Not a Keyorix defect (v4 has no live caller);
	// v3 (the reachable side) drops the clip newline in this edge case, which is
	// reasonable at end-of-stream. Guarded by: block-scalar header present AND input
	// does not end with `\n`/`\r`.
	"block-scalar-eos-clip": true,

	// D28. D18 compound: anchor-colon absorption extends the anchor name past `:` into
	// a non-ASCII character that v4's anchor scanner rejects with "did not find expected
	// alphabetic or numeric character". v3 ends the anchor at `:` and never sees the
	// non-ASCII character in anchor-name position. Found by the DF3 fuzz run at
	// `&0:0ډ` (testdata/fuzz/FuzzYAMLV4Differential/a9fc9bb63e204a8b). v4 is the
	// stricter side here (rejects). The reachable library (v3) accepts. Not a Keyorix
	// defect (v4 has no live caller). Keyed on the v4 error "did not find expected
	// alphabetic or numeric character" with side "v4-rejects".
	"v4-rejects:anchor-char": true,

	// D29. `<<` merge-key with INVALID merge value: v4 enforces merge-key semantics and
	// rejects when the merge value is not a map or sequence of maps ("map merge requires
	// map or sequence of maps as the value"). v3 treats `<<` as a plain key with nil
	// value and accepts. Found by the DF3 fuzz run at `00000: 00\n0: {<<:}` (testdata/
	// fuzz/FuzzYAMLV4Differential/6abe4fb3590fbcb7). This is the REJECT direction of D22
	// (which covers the ACCEPT-but-silently-drop case). Not a Keyorix defect (v4 has no
	// live caller). v4 is the stricter side. Keyed on "merge requires" / "map merge".
	"v4-rejects:merge-value": true,

	// D30. Block scalar header followed by non-whitespace content (`|\n|A`): v3 re-parses
	// the second `|` as a new block scalar header and rejects with "did not find expected
	// comment or line break"; v4 accepts and treats `|A` as block scalar content at
	// column 0. Found by the DF3 fuzz run at `|\n|A` (testdata/fuzz/
	// FuzzYAMLV4Differential/1dea1d27d66a943b). v3 is stricter: it validates block
	// scalar headers strictly. The reachable library (v3) rejects the input. Not a
	// Keyorix defect (v4 has no live caller). Keyed on "comment or line break".
	"v3-rejects:block-header": true,

	// D31. YAML 1.1 binary integer literal (`0b+0`, `0b1`, `0b101`): v3.0.5 (YAML 1.1)
	// decodes the `0b` prefix (with optional sign) as a binary integer; v4.0.0 (YAML 1.2)
	// dropped binary literals and treats the whole token as a string. Found by the DF3 fuzz
	// run at `0b+0` (testdata/fuzz/FuzzYAMLV4Differential/71de6c43bb10a32d). v4 is the more
	// spec-correct side (YAML 1.2 core schema dropped 0b); the reachable library (v3) silently
	// converts `0b+0` to integer 0. Not a Keyorix defect (v4 has no live caller); forward-
	// looking migration hazard for YAML 1.1 binary number literals. Recognised by regex
	// `^[-+]?0[bB][-+]?[0-1_]+$` on the whole input (bare scalar only).
	"yaml11-binary-int": true,
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
		// Use an error that contains "did not find expected" but NOT "directive", "key",
		// "node content", or any other specifically-classified substring, so the generic
		// :syntax case is what actually fires.
		other := classifyYAMLV4Split(&yamlErr{"yaml: did not find expected block entry"}, nil)
		if other != "v3-rejects:syntax" || yamlV4ExpectedDiff[other] {
			t.Fatalf("a generic v3 syntax error must stay the untolerated :syntax class, got %q", other)
		}
		t.Logf("oracle-2 flow-node-content gating proven: '[: 1]' tolerated; generic syntax still fails")
	}

	// ---- Oracle 3 class gating: flow-SEQUENCE colon-no-space (D24) ----
	{
		in := []byte("[0:]")
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
			t.Fatalf("precondition: `[0:]` v3/v4 must disagree (v3=%q v4=%q)", cb3, cb4)
		}
		if class := classifyYAMLV4ValueSplit(in, v3v, v4v); class != "flow-seq-colon-nospace" || !yamlV4ExpectedDiff[class] {
			t.Fatalf("`[0:]` must class as the tolerated flow-seq-colon-nospace, got %q (v3=%#v v4=%#v)", class, v3v, v4v)
		}
		// RED: an input without `:]` must not be recognised.
		if isFlowSeqColonNoSpaceDivergence([]byte("[0: 1]"), []any{"0: 1"}, []any{map[string]any{"0": 1}}) {
			t.Fatalf("an input without `:]` must not be recognised as flow-seq-colon-nospace")
		}
		// RED: a genuine divergence where the space-insertion changes v4 must NOT be absorbed.
		if isFlowSeqColonNoSpaceDivergence([]byte("a: 1"), map[string]any{"a": 1}, map[string]any{"a": 2}) {
			t.Fatalf("a genuine non-colon-nospace divergence must not be absorbed")
		}
		t.Logf("oracle-3 D24 flow-seq-colon gating proven: `[0:]` tolerated causally")
	}

	// ---- Oracle 2 class gating: v4-rejects:empty-implicit-key (D25) ----
	// The INVERSE direction of D2: v4 rejects where v3 accepts, with the same
	// "did not find expected key" error message on the v4 side.
	{
		in := []byte("0: &0:0000000,")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 != nil || err4 == nil {
			t.Fatalf("precondition: '0: &0:0000000,' must be accepted by v3 and rejected by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v4-rejects:empty-implicit-key" {
			t.Fatalf("split must class as v4-rejects:empty-implicit-key, got %q (v4err=%v)", class, err4)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("v4-rejects:empty-implicit-key must be listed (tolerated)")
		}
		// RED: the class is directional — v3-rejects:empty-implicit-key (D2) must NOT
		// absorb a v4-rejects split, and vice versa.
		if class == "v3-rejects:empty-implicit-key" {
			t.Fatalf("the v4-side rejection must not be confused with the v3-side D2 class")
		}
		// GREEN: D2 (v3 rejects, v4 accepts) is STILL its own distinct class.
		var z3, z4 any
		e3D2 := v3yaml.Unmarshal([]byte(":"), &z3)
		e4D2 := v4yaml.Unmarshal([]byte(":"), &z4)
		if classifyYAMLV4Split(e3D2, e4D2) != "v3-rejects:empty-implicit-key" {
			t.Fatalf("D2 ':' split must still class as v3-rejects:empty-implicit-key")
		}
		t.Logf("oracle-2 D25 v4-rejects:empty-implicit-key gating proven; D2 unchanged")
	}

	// ---- Oracle 2 class gating: v3-rejects:indentation-indicator (D26) ----
	// This split manifests in multi-doc mode (the second document is `>0` with
	// indentation indicator 0). Test it via decodeStreamV3/decodeStreamV4 to match
	// the oracle that finds it.
	{
		in := []byte(">\n>0")
		_, err3 := decodeStreamV3(in)
		_, err4 := decodeStreamV4(in)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: `>\\n>0` stream must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:indentation-indicator" {
			t.Fatalf("`>\\n>0` split must class as v3-rejects:indentation-indicator, got %q (v3err=%v)", class, err3)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("v3-rejects:indentation-indicator must be listed (tolerated)")
		}
		// RED: a different v3 error must NOT be absorbed by this class.
		other := classifyYAMLV4Split(&yamlErr{"yaml: some other parse error"}, nil)
		if other == "v3-rejects:indentation-indicator" {
			t.Fatalf("an unrelated v3 error must not class as indentation-indicator")
		}
		t.Logf("oracle-2 D26 indentation-indicator gating proven; other v3 errors still fail")
	}

	// ---- Oracle 3 class gating: block-scalar EOS clip (D27) ----
	{
		in := []byte("|\n 000000\n  ")
		var v3v, v4v any
		if err := v3yaml.Unmarshal(in, &v3v); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(in, &v4v); err != nil {
			t.Fatal(err)
		}
		cb3, e3 := v3yaml.Marshal(v3v)
		cb4, e4 := v3yaml.Marshal(v4v)
		if e3 != nil || e4 != nil {
			t.Fatal(e3, e4)
		}
		if reflect.DeepEqual(cb3, cb4) {
			t.Fatalf("precondition: D27 input must diverge (v3=%q v4=%q)", cb3, cb4)
		}
		if class := classifyYAMLV4ValueSplit(in, v3v, v4v); class != "block-scalar-eos-clip" || !yamlV4ExpectedDiff[class] {
			t.Fatalf("`|\\n 000000\\n  ` must class as block-scalar-eos-clip, got %q (v3=%#v v4=%#v)", class, v3v, v4v)
		}
		// GREEN: adding a trailing newline makes both parsers agree (no divergence).
		inNL := append(append([]byte{}, in...), '\n')
		var v3nl, v4nl any
		if err := v3yaml.Unmarshal(inNL, &v3nl); err != nil {
			t.Fatal(err)
		}
		if err := v4yaml.Unmarshal(inNL, &v4nl); err != nil {
			t.Fatal(err)
		}
		cnl3, _ := v3yaml.Marshal(v3nl)
		cnl4, _ := v3yaml.Marshal(v4nl)
		if !reflect.DeepEqual(cnl3, cnl4) {
			t.Fatalf("adding trailing newline must resolve D27 divergence (v3=%q v4=%q)", cnl3, cnl4)
		}
		// RED: an input that ends with \n must NOT be absorbed by this class.
		inWithNL := []byte("|\n 000000\n")
		var v3wn, v4wn any
		_ = v3yaml.Unmarshal(inWithNL, &v3wn)
		_ = v4yaml.Unmarshal(inWithNL, &v4wn)
		if class2 := classifyYAMLV4ValueSplit(inWithNL, v3wn, v4wn); class2 == "block-scalar-eos-clip" {
			t.Fatalf("an input ending with \\n must not class as block-scalar-eos-clip")
		}
		// RED: a non-block-scalar value diff must NOT be absorbed.
		if class3 := classifyYAMLV4ValueSplit([]byte("x"), "foo", "foo\n"); class3 == "block-scalar-eos-clip" {
			t.Fatalf("a non-block-scalar +newline diff must not class as block-scalar-eos-clip")
		}
		t.Logf("oracle-3 D27 block-scalar-eos-clip gating proven; trailing-newline inputs still fail")
	}

	// ---- Oracle 2 class gating: v4-rejects:anchor-char (D28) ----
	{
		in := []byte("&0:0ډ")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 != nil || err4 == nil {
			t.Fatalf("precondition: `&0:0ډ` must be accepted by v3 and rejected by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v4-rejects:anchor-char" {
			t.Fatalf("`&0:0ډ` split must class as v4-rejects:anchor-char, got %q (v4err=%v)", class, err4)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("v4-rejects:anchor-char must be listed (tolerated)")
		}
		// RED: the v3-rejects:anchor-char direction (D9) must remain distinct.
		var z3, z4 any
		e3D9 := v3yaml.Unmarshal([]byte("o: &!0000"), &z3)
		e4D9 := v4yaml.Unmarshal([]byte("o: &!0000"), &z4)
		if classifyYAMLV4Split(e3D9, e4D9) != "v3-rejects:anchor-char" {
			t.Fatalf("D9 `o: &!0000` split must still class as v3-rejects:anchor-char (direction unchanged)")
		}
		t.Logf("oracle-2 D28 v4-rejects:anchor-char gating proven; D9 direction unchanged")
	}

	// ---- Oracle 2 class gating: v4-rejects:merge-value (D29) ----
	{
		in := []byte("0: {<<:}")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 != nil || err4 == nil {
			t.Fatalf("precondition: `0: {<<:}` must be accepted by v3 and rejected by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v4-rejects:merge-value" {
			t.Fatalf("`0: {<<:}` split must class as v4-rejects:merge-value, got %q (v4err=%v)", class, err4)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("v4-rejects:merge-value must be listed (tolerated)")
		}
		// RED: D22 (merge-key value divergence, both accept) must remain distinct.
		var z3, z4 any
		e3D22 := v3yaml.Unmarshal([]byte("<<"), &z3)
		e4D22 := v4yaml.Unmarshal([]byte("<<"), &z4)
		if e3D22 != nil || e4D22 != nil {
			t.Fatalf("precondition: `<<` must be accepted by both (v3=%v v4=%v)", e3D22, e4D22)
		}
		// D22 is a value split, not an accept/reject split — classifyYAMLV4Split is not
		// called for it. Verify v3val != v4val (the value split still fires).
		cb3, _ := v3yaml.Marshal(z3)
		cb4, _ := v3yaml.Marshal(z4)
		if reflect.DeepEqual(cb3, cb4) {
			t.Fatalf("D22 `<<` must still produce a value split (v3=%q v4=%q)", cb3, cb4)
		}
		t.Logf("oracle-2 D29 v4-rejects:merge-value gating proven; D22 value split still fires")
	}

	// ---- Oracle 2 class gating: v3-rejects:block-header (D30) ----
	{
		in := []byte("|\n|A")
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(in, &v3v)
		err4 := v4yaml.Unmarshal(in, &v4v)
		if err3 == nil || err4 != nil {
			t.Fatalf("precondition: `|\\n|A` must be rejected by v3 and accepted by v4 (v3=%v v4=%v)", err3, err4)
		}
		class := classifyYAMLV4Split(err3, err4)
		if class != "v3-rejects:block-header" {
			t.Fatalf("`|\\n|A` split must class as v3-rejects:block-header, got %q (v3err=%v)", class, err3)
		}
		if !yamlV4ExpectedDiff[class] {
			t.Fatalf("v3-rejects:block-header must be listed (tolerated)")
		}
		// RED: a generic "did not find expected" error (not "comment or line break")
		// must NOT be absorbed by this class.
		other := classifyYAMLV4Split(&yamlErr{"yaml: did not find expected block entry"}, nil)
		if other == "v3-rejects:block-header" {
			t.Fatalf("a generic 'did not find expected' error must not class as block-header")
		}
		t.Logf("oracle-2 D30 v3-rejects:block-header gating proven; generic syntax still fails")
	}

	// ---- Oracle 3 class gating: YAML 1.1 binary integer literal (D31) ----
	// v3 (YAML 1.1) decodes `0b+0` as binary integer 0; v4 (YAML 1.2) decodes it as string.
	// Also covers the container case: `0: 0b+0` → v3 {0:0} vs v4 {0:"0b+0"}.
	{
		for _, in := range [][]byte{
			[]byte("0b+0"),      // bare scalar (testdata seed 71de6c43bb10a32d)
			[]byte("0: 0b+0"),   // value inside a map (testdata seed 70f8e3e01bc42e7e)
		} {
			var v3v, v4v any
			if err := v3yaml.Unmarshal(in, &v3v); err != nil {
				t.Fatalf("D31 %q: v3 unmarshal error: %v", in, err)
			}
			if err := v4yaml.Unmarshal(in, &v4v); err != nil {
				t.Fatalf("D31 %q: v4 unmarshal error: %v", in, err)
			}
			cb3, _ := v3yaml.Marshal(v3v)
			cb4, _ := v3yaml.Marshal(v4v)
			if reflect.DeepEqual(cb3, cb4) {
				t.Fatalf("precondition: D31 input %q v3/v4 must disagree (v3=%q v4=%q)", in, cb3, cb4)
			}
			if class := classifyYAMLV4ValueSplit(in, v3v, v4v); class != "yaml11-binary-int" || !yamlV4ExpectedDiff[class] {
				t.Fatalf("%q must class as the tolerated yaml11-binary-int, got %q (v3=%#v v4=%#v)", in, class, v3v, v4v)
			}
		}
		// RED: a standard decimal integer must not match the regex.
		if yaml11BinaryIntRe.MatchString("42") {
			t.Fatalf("a standard decimal integer must not match yaml11BinaryIntRe")
		}
		// RED: a byte string starting with 0b but with an invalid binary digit (2) must not match.
		if yaml11BinaryIntRe.MatchString("0b2") {
			t.Fatalf("0b2 (digit 2 not in binary set) must not match yaml11BinaryIntRe")
		}
		// RED: a genuine int-vs-string mismatch where the string is NOT a binary int literal
		// must stay value-mismatch (not absorbed by the structural checker).
		notBin := classifyYAMLV4ValueSplit([]byte("x: 42"), map[string]any{"x": 42}, map[string]any{"x": "42"})
		if notBin != "value-mismatch" {
			t.Fatalf("a non-binary-int int-vs-string mismatch must stay value-mismatch, got %q", notBin)
		}
		// RED: a re-parse mismatch (int 5 vs string "0b+0" which decodes to 0) must NOT be absorbed.
		{
			diffs, ok := yaml11BinaryIntVsStringOnly(5, "0b+0")
			if ok && diffs > 0 {
				t.Fatalf("int 5 vs string '0b+0' (which decodes to 0) must NOT be absorbed by yaml11BinaryIntVsStringOnly")
			}
		}
		t.Logf("oracle-3 D31 yaml11-binary-int gating proven: `0b+0` and `0: 0b+0` tolerated; genuine mismatches still fail")
	}
}

// TestYAMLV4AllowlistEntriesHitBySeed verifies that every entry in yamlV4ExpectedDiff
// is exercised (classified) by at least one committed seed. A dead entry — an allowlist
// key that nothing ever classifies to — is a stale claim that could silently cover an
// otherwise-failing input. This test has the same role as TestRefDiffAllowlistNoDead.
//
// Seeds cover all three oracles that use yamlV4ExpectedDiff:
//   - single-doc (Unmarshal) seeds cover the accept/reject and value classes
//   - multi-doc stream seeds cover the stream-only split classes
//     (v3-rejects:mapping-key-context, v3-rejects:doc-start, v3-rejects:indentation-indicator)
func TestYAMLV4AllowlistEntriesHitBySeed(t *testing.T) {
	hit := map[string]bool{}

	// Single-doc oracle: run seed bytes through v3/v4 Unmarshal and classify any split.
	runSingle := func(data []byte) {
		var v3v, v4v any
		err3 := v3yaml.Unmarshal(data, &v3v)
		err4 := v4yaml.Unmarshal(data, &v4v)
		a3, a4 := err3 == nil, err4 == nil
		if a3 != a4 {
			hit[classifyYAMLV4Split(err3, err4)] = true
			return
		}
		if !a3 {
			return
		}
		cb3, m3 := v3yaml.Marshal(v3v)
		cb4, m4 := v3yaml.Marshal(v4v)
		if m3 != nil || m4 != nil {
			return
		}
		if !reflect.DeepEqual(cb3, cb4) {
			hit[classifyYAMLV4ValueSplit(data, v3v, v4v)] = true
		}
	}

	// Multi-doc oracle: classify stream-level accept/reject splits.
	runMultiDoc := func(data []byte) {
		_, err3 := decodeStreamV3(data)
		_, err4 := decodeStreamV4(data)
		if (err3 == nil) != (err4 == nil) {
			hit[classifyYAMLV4Split(err3, err4)] = true
		}
	}

	// Single-doc seeds (FuzzYAMLV4Differential in-code corpus + testdata seeds).
	for _, s := range []string{
		// D1 nonspecific-tag-empty-scalar
		"!", "a: !", "- !",
		// D12 nonspecific-tag-nonempty-scalar
		"! 00", "! true", "! null", "! 1.5",
		// D17 nonspecific-tag-structural
		"! : 00", "! 00 : x",
		// D18 anchor-name-colon-boundary
		"&a:b", "&00:00000", "k: &00:00000",
		// D10 negative-zero-int-vs-float
		"- -0",
		// D19 negative-zero-structural
		"-0:",
		// D20 v3-rejects:unexpected-eos
		"|\n\"",
		// D21 v3-rejects:directive
		"|\n%0",
		// D22 merge-key-handling
		"<<", "a: <<", "- <<",
		// D23 flow-map-colon-nospace
		"0: {0:} ",
		// D2 v3-rejects:empty-implicit-key
		":", "- :\n",
		// D3 v3-rejects:control-char
		"\x7f",
		// D4 v4-rejects:doc-start
		"0\n:",
		// D5 v4-rejects:tag-char
		"!,",
		// D6 v4-rejects:comment-ws
		"|#0",
		// D7 v3-rejects:token-start
		"\t",
		// D8 block-scalar-underindent
		"|\n00", ">\n0x",
		// D9 v3-rejects:anchor-char
		"o: &!0000",
		// D11 v3-rejects:flow-ws
		"{!}",
		// D15 v3-rejects:flow-seq-tagged-empty
		"[!x]", "[0: !]",
		// D16 v3-rejects:flow-node-content
		"[: 1]",
		// D24 flow-seq-colon-nospace (testdata seed 28731c901e37d1c2)
		"[0:]",
		// D25 v4-rejects:empty-implicit-key (testdata seed 05ca5f53b4ce7568)
		"0: &0:0000000,",
		// D27 block-scalar-eos-clip (testdata seed 597ac6ec0bae9ae4)
		"|\n 000000\n  ",
		// D28 v4-rejects:anchor-char (testdata seed a9fc9bb63e204a8b)
		"&0:0ډ",
		// D29 v4-rejects:merge-value (testdata seed 6abe4fb3590fbcb7)
		"0: {<<:}",
		// D30 v3-rejects:block-header (testdata seed 1dea1d27d66a943b)
		"|\n|A",
		// D31 yaml11-binary-int (testdata seeds 71de6c43bb10a32d, 70f8e3e01bc42e7e)
		"0b+0", "0: 0b+0",
	} {
		runSingle([]byte(s))
	}

	// Multi-doc seeds: classes that only manifest in a stream decode.
	for _, s := range []string{
		// v3-rejects:mapping-key-context (FuzzYAMLV4MultiDocDifferential in-code seed)
		"&0?",
		// v3-rejects:doc-start (FuzzYAMLV4MultiDocDifferential in-code seed)
		">\n0",
		// D26 v3-rejects:indentation-indicator (testdata seed 9a8b08fc667ea076)
		">\n>0",
	} {
		runMultiDoc([]byte(s))
	}

	for class := range yamlV4ExpectedDiff {
		if !hit[class] {
			t.Errorf("allowlist entry %q is not hit by any seed — add a seed to this test or remove the entry", class)
		}
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
