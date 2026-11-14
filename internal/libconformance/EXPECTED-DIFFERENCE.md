# EXPECTED-DIFFERENCE table — "one bug class, many libraries"

This is the committed registry of *named* disagreement classes for the BC1
binary-format round-trip / bounded-work targets. The point of the table (and the
talk slide behind it): the SAME four bug classes from the digitorus/pkcs7 upstream
results — (1) length bombs, (2) out-of-bounds slicing, (3) padding/unwrap panics,
(4) round-trip divergence — are checked against several binary parsers at once with
ONE oracle shape each. A target fails only when it hits a disagreement **not** in
this table. Everything listed here is a known, benign property of the library, so a
hit on it is noise to be suppressed, not a finding.

Columns: Class · Library/target · What differs · Why it is EXPECTED · Where handled.

| # | Class | Library / target | What differs | Why EXPECTED (not a bug) | Where handled |
|---|-------|------------------|--------------|--------------------------|---------------|
| E1 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | `float64` NaN ≠ NaN, at any depth incl. inside a `cbor.Tag.Content` (found by fuzzing: `c8fb…` = tag8(NaN); NaN payloads also normalize to float16 `f97e00`) | IEEE-754: NaN is unequal to itself under `reflect.DeepEqual`; the value round-trips fine | `nanAwareEqual` treats NaN==NaN and recurses through `cbor.Tag` |
| E2 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | a tag-2/3 bignum that fits in 64 bits decodes to `big.Int` on one pass and `int64`/`uint64` on the other | fxamacker picks the narrowest Go type; magnitude is preserved | `asBigInt` numeric compare |
| E3 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | indefinite-length array/map/string collapses to definite-length on re-encode | CBOR §3.2: indefinite and definite forms denote the same value | property stated on `v1↔v2`; `data↔v1` not asserted |
| E4 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | duplicate map keys: later value wins, earlier dropped | default DecMode is `DupMapKeyQuiet`; the map value is well-defined (last-wins) | normalized by the first decode |
| E5 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | map key ORDER changes across re-encode; a KEY can also be normalized by its own class (a tag-1 datetime key becomes an int key — found by fuzzing `{tag1(-17):-17}`) | Go map iteration is unordered; CBOR maps are unordered unless a canonical EncMode is used; keys are values and normalize like values | compare does O(n²) set-matching with `nanAwareEqual` on keys, not a Go `==` lookup |
| E6 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | non-canonical integer/float width normalizes (e.g. a float stored wide shrinks) | shortest-form encoding denotes the same number | normalized by the first decode |
| E7 | Length-bomb | cbor/v2 `FuzzCBORBoundedWork` | a 2^64-1 array/map/bignum/string head is *rejected cheaply* (error, no alloc) rather than processed | default DecMode caps `MaxArrayElements`/`MaxMapPairs`=131072, `MaxNestedLevels`=32; this is the DEFENSE working, the EXPECTED pass | oracle asserts bounded work, not acceptance |
| E8 | OOB / bounded | go-tpm `FuzzTPMUnmarshalBoundedWork` | a TPM2B length prefix larger than the remaining buffer is rejected (error) not read past | go-tpm validates length prefixes against remaining bytes before copying | oracle asserts no-panic + bounded alloc |
| E9 | Scope | go-tpm `FuzzTPMUnmarshalBoundedWork` | a hit confined to `TPMTPublic`/`TPMSAttest`/`TPM2BAttest` is UPSTREAM-only, not a Keyorix reachability claim | only `TPM2BPublic`/`TPM2BPrivate` have a traced live Keyorix caller | triage classifies by tripped type |
| E10 | Scope | cbor/v2 (all) | CBOR findings are INDIRECT-only w.r.t. Keyorix | no direct Keyorix import; reached via go-webauthn attestation decode | reachability trace required before any Keyorix claim |
| E11 | Round-trip | cbor/v2 `FuzzCBORRoundTrip` | **FOUND BY FUZZING** (input `c130`): tag-0/1 datetime decodes to `time.Time`, re-encodes as an UNTAGGED Unix number → type changes `time.Time`→`int64`/`float64` and the tag is dropped. Sub-case (`c1faffff3030`): a tag-1 epoch of NaN/Inf, and any ZERO `time.Time`, re-encode to CBOR `null` → `nil` | default EncMode encodes `time.Time` as `TimeUnix` and a zero time as `null`; the *instant* is preserved, only the tag/Go-type representation changes. Documented fxamacker behavior, benign for Keyorix (go-webauthn uses no datetime tags) | `sameInstant` compares by Unix second, and treats zero-time↔nil as equal; reproducers kept as regression seeds |

## Padding / unwrap panic class (class 3) — note

The upstream pkcs7 CBC-unpad panic has no direct analogue in CBOR / TPM / COSE:
none of these formats has a PKCS#7-style block-cipher pad. The class is still
*covered* because the never-panic half of each bounded-work oracle (a panic in the
guarded decode propagates and is recorded by the Go fuzzer natively) would catch an
unwrap/slice panic wherever it occurred — e.g. a COSE key whose declared coordinate
length exceeds the decoded byte string. No padding-specific oracle is added; see the
report's "what the oracle does NOT verify" for each target.
