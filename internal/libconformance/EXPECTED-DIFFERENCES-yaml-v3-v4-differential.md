# Expected-difference table — YAML v3→v4 differential oracle (DF2)

Oracle `FuzzYAMLV4Differential` (`yaml_v4_differential_fuzz_test.go`) asserts, for the same
input bytes, that the two go.yaml.in implementations this module links behave identically:

- **`go.yaml.in/yaml/v3` v3.0.5** — the ecosystem's canonical home for the YAML library
  Keyorix tooling imports (byte-identical to the `go.yaml.in/yaml/v3` side traced live in
  `FuzzYAMLSiblingDifferential`). **Reachable.**
- **`go.yaml.in/yaml/v4` v4.0.0** — the major-version rewrite the ecosystem is migrating to,
  already in this module's graph. **No live Keyorix caller today** — a forward-looking
  migration-risk oracle.

Three oracles (all non-panic; a panic in either library is a native finding):

1. **Bounded work** — each `Unmarshal` metered with resguard; a super-linear alloc/malloc
   blow-up in EITHER library (relative to a calibrated absolute ceiling) fails.
2. **Accept/reject parity** — a split accept/reject verdict fails unless its class is listed
   below (`yamlV4ExpectedDiff`).
3. **Decoded-value equality** — when both accept, the two decoded values must canonicalise
   (one fixed v3 encoder) to the same bytes, unless the divergence class is listed below.

This table is the talk slide **"where a major-version rewrite of the same library quietly
changes behaviour."** Every row is a divergence that is KNOWN and justified, so only a NEW
class reaches the failing assertion.

## Accept/reject and value divergences (the table)

| id | class key | what diverges | v3.0.5 | v4.0.0 | why it is tolerated | enforced by |
|----|-----------|---------------|--------|--------|---------------------|-------------|
| D1 | `nonspecific-tag-empty-scalar` | the non-specific tag `!` applied to an **empty** scalar node (`!`, `a: !`, `- !`) | resolves to **null** | resolves to the **empty string** (`!!str`) | v4 is the more spec-aligned reading: the `!` non-specific tag forces resolution off the null default, and the failsafe schema resolves a `!`-tagged scalar as `!!str`. A deliberate v4 rewrite change, **not a Keyorix defect** — v4 has no live caller. Plain empty nodes (`a:`, `~`, `null`) decode to null in BOTH; an explicit `!!str` decodes to `""` in BOTH; only the bare `!` diverges. | `classifyYAMLV4ValueSplit` / `nilVsEmptyStringOnly` — tolerates ONLY null-vs-`""` leaves with otherwise-identical structure; any other value diff (different number, key set, or a nil-vs-**non-empty**-string) stays `value-mismatch` and fails. |
| D2 | `v3-rejects:empty-implicit-key` | a mapping entry with an **empty implicit key** — a line beginning with the value indicator `:` (`:`, `: `, `:\n`, `- :`, `a:\n:`) | **rejects** (`did not find expected key`) | **accepts** as a null key → null value (`{null: null}`) | Both readings are defensible — YAML permits an empty/implicit key — and v4 is the more permissive. This is the **security-relevant direction** (v4 accepts what v3 rejects): on a v3→v4 migration a config line rejected today would silently parse as a null-keyed mapping, so a validator-on-v3 / consumer-on-v4 split would be a parser-differential bypass. **Not a Keyorix defect today** (v4 has no live caller); a forward-looking migration/validation-parity hazard. | `classifyYAMLV4Split` — the class is keyed on the v3 error `did not find expected key` ALONE, so it does not tolerate any other v3 syntax rejection (`did not find expected node content`, `expected alphabetic…`, etc. stay `:syntax`, which is absent from the table and fails). |
| D3 | `v3-rejects:control-char` | **DEL (0x7F) and the C1 control range (0x80–0x9F, except NEL 0x85)** in scalar content, bare (`"\x7f"`) or embedded (`k: a\x7fb`) | **rejects** (`control characters are not allowed`) | **accepts**, keeping the control byte in the decoded string | C0 controls (0x00–0x1F, except tab/LF/CR) are rejected by BOTH; NEL (0x85) and NBSP (0xA0) accepted by BOTH; only DEL + C1 split. v3 is the **stricter/safer** side — v4 relaxed the printable-character policy. **Most migration-sensitive class**: on a v3→v4 bump, control characters (terminal escape sequences, DEL) rejected today would pass into config string values. **Not a Keyorix defect today** (v4 has no live caller); a forward-looking hazard and an upstream HARDENING note on v4's relaxed control-char validation. | `classifyYAMLV4Split` — keyed on the v3 error `control characters are not allowed` ALONE. |
| D4 | `v4-rejects:doc-start` | a plain scalar followed by a value indicator `:` at the **start of the next line** (`0\n:`, `a\n: b`, `0\n: x`) | **accepts**, keeping ONLY the leading scalar (`0\n:` → int `0`) and **silently dropping** line 2 | **rejects** (`did not find expected <document start>`) | The OPPOSITE direction from D2/D3: here **v4 is the stricter/safer** side and **v3 silently truncates** the input. The reachable library (v3) is the lenient one, so this is an upstream-style observation about v3's silent-drop on malformed multi-line scalar-vs-mapping input — **not a Keyorix defect** (no code feeds such malformed YAML to a security decision), but worth noting as a v3 footgun. | `classifyYAMLV4Split` — keyed on the v4 error `expected <document start>` ALONE; the red/green also asserts v3 decodes `0\n:` to exactly `0` (the silent truncation). |
| D5 | `v4-rejects:tag-char` | a flow indicator (`,` `[` `]`) in a **non-verbatim tag suffix** (`!,`, `!tag[`, `a: !,x`, `x: !!str,`) | **accepts** (lenient — ends the tag before the flow char, rest becomes content) | **rejects** (`found character '…' that is not allowed in a YAML tag`) | `!{`/`!}` are rejected by BOTH; a verbatim `!<a,b>` is accepted by BOTH; only the non-verbatim flow-char suffix splits. **v4 is the more spec-correct** side (flow indicators are not valid tag characters). Same strictness direction as D4 (v4 stricter). **Not a Keyorix defect** (v4 has no live caller); a forward-looking strictness change. | `classifyYAMLV4Split` — keyed on the v4 error `not allowed in a YAML tag` ALONE. |
| D6 | `v4-rejects:comment-ws` | a `#` comment **not preceded by whitespace** (`|#0`, and similar) | **accepts** (lenient) | **rejects** (`found a comment without preceding whitespace`) | The YAML spec requires a comment `#` to be preceded by whitespace (or start-of-line). **v4 enforces it, v3 does not** — same strictness direction as D4/D5. **Not a Keyorix defect** (v4 has no live caller); a forward-looking strictness change. | `classifyYAMLV4Split` — keyed on the v4 error `comment without preceding whitespace` ALONE. |

| D7 | `v3-rejects:token-start` | a leading character v3's scanner refuses to start a token with — notably a bare **TAB** (`"\t"`) | **rejects** (`found character that cannot start any token`) | **accepts** as an empty document (`nil`) | Other chars with the same v3 error (`@`, backtick) are rejected by BOTH; only the leading-TAB case splits. v4 accepts what v3 rejects, but benignly (empty/nil doc). **Not a Keyorix defect** (v4 has no live caller). | `classifyYAMLV4Split` — keyed on the v3 error `cannot start any token` ALONE. |

| D8 | `block-scalar-underindent` | a `|`/`>` block scalar followed by content at **insufficient indentation** (`|\n00`, `>\nx`, `|-\n0\n1` — content at column 0) | decodes the scalar as the **empty string**, **silently dropping** the content | **captures** the content (`"00"`, `"x"`, `"0\n1"`) | A **value-level divergence in the reachable, security-relevant direction**: the library Keyorix tooling uses (v3) **silently loses block-scalar content** on a mis-indented document. Properly-indented block scalars (`|\n  00`) agree in BOTH. **Not a Keyorix defect today** (no code feeds such malformed YAML to a security decision), but a genuine **v3 silent-data-loss footgun** worth reporting upstream. | `classifyYAMLV4ValueSplit` — recognised ONLY when every differing leaf is v3-`""` vs a non-empty v4 string AND `inputHasBlockScalarHeader(data)` matches; the red/green proves the same empty-vs-nonempty shape WITHOUT a block header stays `value-mismatch` (fails). |

| D9 | `v3-rejects:anchor-char` | an anchor/alias **name** containing a character v3 forbids there (`&!0000` — anchor name with `!`) | **rejects** (`did not find expected alphabetic or numeric character`) | **accepts** (lenient anchor naming) | v4 accepts what v3 rejects, but benignly — the anchor name does not affect the resolved value. **Not a Keyorix defect** (v4 has no live caller). | `classifyYAMLV4Split` — keyed on the v3 anchor-char error ALONE. |

| D10 | `negative-zero-int-vs-float` | the literal **`-0`** | resolves to **int `0`** | resolves to **float64 negative zero** (`-0.0`) | Every other number tested (`+0`, `-0.0`, `0x0`, `010`, `1e3`, …) agrees in BOTH; only the bare `-0` splits. A genuine but tiny type/value divergence — a config `-0` would be an int in v3, a float in v4. **Not a Keyorix defect** (v4 has no live caller). | `classifyYAMLV4ValueSplit` — recognised only for int-`0`-vs-float-negative-zero leaves; a non-negzero int-vs-float diff stays `value-mismatch` (fails). |

| D11 | `v3-rejects:flow-ws` | a tag/node in **flow context** lacking the whitespace v3 requires after it (`{!}` — a `!`-tagged empty node in a flow mapping) | **rejects** (`did not find expected whitespace or line break`) | **accepts** (lenient) | v4 accepts what v3 rejects — same flow/tag-leniency family as D5/D9, benign. **Not a Keyorix defect** (v4 has no live caller). | `classifyYAMLV4Split` — keyed on the v3 flow-ws error ALONE. |

| D12 | `nonspecific-tag-nonempty-scalar` | the non-specific tag `!` applied to a **NON-empty** scalar (`! 00`, `! 123`, `! true`, `! null`, `! 1.5`, `a: ! 123`, `- ! 00`) | v3 **ignores** the `!` and applies its normal implicit schema (`! 00`→int `0`, `! true`→bool, `! null`→nil, `! 1.5`→float) | v4 treats `!` as forcing the failsafe **`!!str`** resolution and keeps the **raw string** (`"00"`, `"true"`, `"null"`, `"1.5"`) | The **generalisation of D1** from the empty scalar to any non-empty one (DF2 leftover #1). Same root cause: v4 honours the non-specific tag as `!!str`, v3 does not. `! abc` agrees (both `"abc"`) because `abc` resolves to a string in v3 anyway. The live caller (`gopkg.in/yaml.v3` v3.0.1) was verified byte-identical to v3.0.5 on every case here, so the v3 side is the reachable one. **Not a Keyorix defect** (v4 has no live caller); a forward-looking migration hazard (a config `key: ! 00` flips from int `0` to `"00"`). | `classifyYAMLV4ValueSplit` / `nonspecificTagNonEmptyScalarOnly` — recognised ONLY when every differing leaf is "v4 kept the raw string `s` and v3's value is exactly the v3 implicit resolution of `s`" AND the input carries a non-specific `!` tag; a non-resolving int-vs-string diff (v3 `5` vs v4 `"6"`) or the same shape WITHOUT a `!` tag stays `value-mismatch` and fails. |

| D15 | `v3-rejects:flow-seq-tagged-empty` | a tag (`!`, `!local`) on an **empty** node inside a **flow sequence** (`[!x]`, `[0: !]`, `[a: !x]`, `[1: !]`) | **rejects** (`did not find expected ',' or ']'`) — v3's flow scanner cannot handle a tag with no node content before the separator | **accepts**, resolving the tagged-empty node to `""` | Found by the DF3 struct fuzzer at `0: [0: !0000000]`. A tag on a NON-empty flow scalar (`[0: !t 1]`) is accepted by BOTH, so only the tagged-EMPTY-in-flow case splits. Same v4-lenient flow family as D11 (`{!}`), different container/error. **v4 accepts what v3 rejects** (the security-relevant direction) but benignly. Not a Keyorix defect (v4 has no live caller); forward-looking flow-leniency migration note. | `classifyYAMLV4Split` — keyed on the v3 error substring `',' or ']'` alone. |
| D16 | `v3-rejects:flow-node-content` | an **empty key/node** in **flow context** (`[: 1]`) | **rejects** (`did not find expected node content`) | **accepts** as a null-keyed single-pair map element | Found by the DF3 fuzz run. The flow-context analogue of D2 (block empty-implicit-key). **v4 accepts what v3 rejects** (benign — a null key). Not a Keyorix defect (v4 has no live caller); forward-looking flow-leniency migration note. | `classifyYAMLV4Split` — keyed on the v3 error `did not find expected node content`; a generic syntax error still falls through to the untolerated `:syntax`. |

| D17 | `nonspecific-tag-structural` | the non-specific `!` tag re-resolution landing in a **KEY** position (`! : 00`, `! 00: x`) | produces a v3 key (nil / typed) — e.g. `{nil: 0}` | produces a v4 **raw-string** key — e.g. `{"": "00"}` | The **KEY-position generalisation of D1/D12**: same root cause (v4 honours `!` as `!!str`, v3 does not), but at a key, so v3 and v4 maps have different keys and the value-only walkers cannot pair entries (they would fall through to `value-mismatch`). Found by the DF3 struct fuzzer at `! : 00`. Recognised by `nonspecificTagEq`, which pairs map entries across the tag transformation at ANY position and still refuses a genuine diff (v3 `5` vs v4 `"6"`, or different keys neither of which is a tag reparse). Scoped to inputs with a `!` tag. Not a Keyorix defect (v4 has no live caller). | `classifyYAMLV4ValueSplit`/`nonspecificTagEq` — red/green proves a genuine key/value diff and an untagged input both stay `value-mismatch`. |

## Pattern observed across D4–D6 (and likely a longer tail)

D4, D5 and D6 are all the SAME shape: **v4.0.0 enforces a YAML-spec strictness rule that
v3.0.5 accepted leniently** (malformed document structure, invalid tag characters, comments
without preceding whitespace). v4 is a from-scratch rewrite with a stricter, more
spec-conformant scanner, so this class of "v4 rejects what v3 lenient-parsed" is expected to
have a **long tail** of further sub-cases (other indicator/whitespace/escape edge cases). Each
is individually triaged and tolerated by its own narrowly-keyed error class; none is a Keyorix
defect (v4 has no live caller). The security-relevant direction is the OPPOSITE one — v4
*accepting* what v3 *rejects* (D2, D3) — which is why those two are called out as migration
hazards while D4–D6 are called out as v4 strictness improvements / v3 leniency footguns.

No OTHER accept/reject (`*-rejects:*`) class is listed: across the seed corpus and the DF2
fuzz run, D2 was the only accept/reject split — every other malformed input (duplicate keys,
complex keys, excessive aliasing, the other syntax errors) was rejected by BOTH; v4 only
re-worded the error text, which `classifyYAMLV4Split` normalises away. A further accept/reject
split the fuzzer finds is a finding until triaged and listed here.

## Companion oracles (DF3): struct decode, multi-document streams, round-trip

The three scope gaps S1/S2/S3 below are now **partially covered** by companion targets in
`yaml_v4_struct_stream_fuzz_test.go` (red/green: `TestYAMLV4StructStreamRedGreen`). Each ties
a typed/stream/round-trip divergence back to the single-doc `any`-path classes above, so it
reuses this whole table rather than inventing a parallel one. The tie: a typed-struct or
per-document divergence is a **finding unless the `any`-path for the same bytes also diverges
by an already-tolerated class** (`structSplitVerdict`); a typed/stream split where the
`any`-path AGREED is new and fails.

- **`FuzzYAMLV4StructDifferential` (S1).** Decodes the same bytes into the real
  `internal/config.Config` family (the server's live strict-load target) and a synthetic
  struct, under v3 and v4 (lenient), plus v3 `KnownFields(true)` vs v4 `WithKnownFields()`
  (strict). New finding surfaced and tolerated: `int: ! 00` → v3 resolves int `0`, v4 keeps
  `"00"` and **cannot construct it into an `int` field, so v4 rejects where v3 accepts** —
  invisible to the `any` path (both accept there), tied to the tolerated D12 class. Strict
  mode also surfaced `v4-strict-rejects:empty-doc` (below).
- **`FuzzYAMLV4MultiDocDifferential` (S3).** Decodes EVERY document of a `---` stream (v3
  `Decoder` loop vs v4 `Loader` loop) and compares the sequence. A differing **document
  count** is class `multidoc:count-mismatch` (NOT in the table → a finding until triaged);
  per-document value splits reuse `classifyYAMLV4ValueSplit`.
- **`FuzzYAMLV4RoundTrip` (S2).** Within EACH library, `decode→encode→decode` and assert the
  re-decode canonicalises to the first decode (idempotence). A non-idempotent round-trip is a
  genuine library footgun; the round-trip tolerance table `yamlV4RoundTripExpectedDiff` is
  EMPTY on purpose.

Strict-mode divergence tolerated by the struct oracle:

| id | class key | what diverges | v3.0.5 (strict `Decoder`) | v4.0.0 (strict `Load`) | why tolerated | enforced by |
|----|-----------|---------------|---------------------------|-------------------------|---------------|-------------|
| D13 | `v4-strict-rejects:empty-doc` | an empty / document-less input decoded in strict mode | **accepts** — `Decoder.Decode` returns `io.EOF`, which `Config.Load` treats as a valid **all-default** config | **rejects** — one-shot `Load(..., WithKnownFields())` returns `yaml: no documents in stream` | A real **migration gotcha of v4's recommended strict `Load` API**, not a field-strictness divergence: an empty config file that loads fine today (all defaults) would be rejected if the loader naively switched to `yaml.Load(data, &cfg, WithKnownFields())`. Not a Keyorix defect (v4 has no live caller; and the equivalent v4 streaming `Loader` would behave like v3). | `classifyTypedSplit`/`yamlV4StructExpectedDiff` — v3-accepts + v4-rejects + the exact `no documents in stream` message; a real unknown-field rejection is NOT absorbed. |
| D14 | `v4-strict-rejects:nonintegral-float-into-int` | a **non-integral float** value decoded into an **integer** struct field (`int: 0.1`, `v: 0.1`) | **accepts** — silently **coerces, truncating `0.1`→ int `0` (DATA LOSS)** | **rejects** — `cannot construct !!float `0.1` into int` | Found by the DF3 struct fuzzer. Integral floats (`5.0`, `1e3`) are accepted by BOTH, so only a NON-integral float splits. v3 is the reachable, lenient, **data-losing** side — the same silent-data-loss footgun family as D8 (block-scalar drop) and D4 (truncation); v4 is strict. Invisible to the `any`-path (both decode `0.1` to the float there). Not a Keyorix defect (v4 has no live caller; a config `int` field receiving a fractional float is exotic) but a genuine **v3 silent-coercion footgun**. | `classifyTypedSplit`/`yamlV4StructExpectedDiff` — keyed on a v4 rejection whose message contains `float` and `into int`; the `!`-tag-into-int rejection (no `float`) and integral floats (no split) are not absorbed. |

## What the companion oracles STILL do NOT verify (residual scope)

- **S1-residual.** `config.Config` typed VALUE equality is only canonical-marshal compared when
  BOTH libraries accept; a nested type with a decode divergence that both still *accept* into
  the same canonical bytes is invisible. Custom `UnmarshalYAML` is not exercised (there are
  none in `internal/`). The synthetic struct covers a fixed field-type spread, not every Go
  kind (no `*int`, `int8`, `uintptr`, embedded-struct-promotion, or `,inline` tag).
- **S2-residual.** Round-trip uses v3's `Marshal` as the fixed canonical comparator, so a
  divergence purely in v4's `Marshal` byte output (indent, quoting, flow style) that still
  re-decodes to the same value is not seen — only value idempotence is asserted, not encoded-
  byte parity between v3 and v4.
- **S3-residual.** The multi-doc oracle compares document COUNT and per-document VALUE; it does
  not assert anything about comments, document-boundary byte positions, or directives
  (`%YAML`, `%TAG`) that do not change the decoded value.
- **S4 — Inputs > 8 KiB.** Bounded to keep a pathological expansion in one library from
  masquerading as a disagreement and to keep the resource model meaningful. A divergence that
  only manifests on megabyte inputs is not covered.
- **S5 — Bounded-work meters.** FATAL meters are `alloc_bytes` and `mallocs` only (the
  ReadMemStats deltas attributable to one input), judged by an ABSOLUTE ceiling. `wall`/`cpu`
  are advisory (process-wide, noisy under load). `live_heap` is NOT fatal (it is the
  whole-process post-GC heap, not a per-input delta — it false-fired at 106 MiB on a 28-byte
  input during DF2 bring-up). Disk/net/sleep/log/DB are not metered (an in-memory parse
  touches none). So a CPU-only quadratic that does not also allocate is seen only via the
  advisory wall/cpu context line, never as a hard fail.
- **S6 — The bounded-work oracle fires on EITHER library, not on a v3-vs-v4 *difference*.**
  An accepted alias fan-out that amplifies memory in BOTH libraries (go.yaml's flat-alias
  fan-out is bounded by its excessive-aliasing cap only for *nested* aliases, not flat ones)
  is a shared go.yaml property, not a v3/v4 divergence. Such a hit is a HARDENING observation
  about go.yaml, reachable via `scripts/fuzzing/configspace`, and is classified as such — not
  as a parser-differential bypass.

## How this list was established to be complete *as of the seeds + DF2 run*

D1 is the only decoded-value divergence and the only split of any kind observed between
v3.0.5 and v4.0.0 across: the 24-entry seed corpus (which exercises duplicate keys, aliases,
merge keys, YAML 1.1/1.2 bool/octal/binary, floats/specials, timestamps, complex keys, block
scalars, multi-doc, the `=` value, and the `!` tag) PLUS the foreground fuzz run recorded in
the DF2 report (`/mnt/data/wave4/out/df2-REPORT.md`). The classifier vocabulary
(`classifyYAMLV4Split`, `classifyYAMLV4ValueSplit`) names every shape the oracle can emit, so
a reviewer can read the full set of recognised classes rather than infer them. A class not in
this table fails the target by construction — the table can only be widened by naming and
justifying a class, never by loosening an assertion.
