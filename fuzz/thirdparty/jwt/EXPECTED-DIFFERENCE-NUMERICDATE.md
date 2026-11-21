# EXPECTED-DIFFERENCE table — golang-jwt/jwt/v5 `NumericDate.UnmarshalJSON`

`FuzzNumericDateDifferential` drives raw bytes straight into
`jwt.NumericDate.UnmarshalJSON` — the decoder the `exp`/`nbf`/`iat`
`RegisteredClaims` fields use on both LIVE Keyorix verify paths
(`internal/oidcverify OIDCVerifier.VerifyWithExpiry`,
`internal/core KeyorixCore.verifyIDToken`) — and compares its result against a
strict RFC 7519 §2 reference (`strictNumericDate` in `claims_codec_test.go`).

golang-jwt's decode is: `json.Unmarshal` into a `json.Number` (rejects a
non-number token and trailing bytes), then `Number.Float64()` (rejects values not
representable as a finite `float64`), then
`time.Unix(int64(round), int64(frac*1e9))` from `math.Modf`. Routing an integer
through `float64` is the source of every class below.

The ONLY blocking assertion is `exact-int`. Every other row is a named,
non-blocking class: the fuzzer still proves no panic / no hang (Guard) and
accept-parity for it, but does not require an exact seconds value.

| Class (reason code) | Condition | golang-jwt behaviour | Why expected / Keyorix impact |
|---|---|---|---|
| `exact-int` (BLOCKING) | integer literal, `\|v\| <= 2^53` | `.Unix() == v` exactly | The live correctness property. `float64` represents every integer up to 2^53 exactly, so no precision is lost; a mismatch here would silently move a token's expiry and is a real defect. Guarded exactly. |
| `float-precision` | integer literal, `2^53 < \|v\| <= MaxInt64` | `.Unix()` within one `float64` ULP of `v` (can differ by up to ~2048 near MaxInt64) | `Number.Float64()` rounds to the nearest representable double, losing the low bits. A real `exp` is ~1.7e9 (far below 2^53), so this only affects absurd timestamps. **Impact: none** — such an `exp` is decades in the future either way; the token's validity verdict is unchanged. The fuzzer still asserts the drift is bounded (ULP-sized), not arbitrary. |
| `overflow` | finite `float64` but `\|v\| > MaxInt64` (e.g. `1e19`, `1e300`) | `int64(round)` conversion is implementation-defined (Go spec); on amd64 it saturates/wraps. No panic. | A value this large is not a real timestamp. The security-relevant direction is that it must NOT land on a believable near-now timestamp that could silently extend a token — pinned by `TestNumericDate_HugeExpIsFailClosed`. **Impact: fail-closed / absurd-future** — never a plausible "valid now". |
| `fraction` | non-integer seconds (`1700000000.5`) or exponent form (`1.5e9`) | truncated to `TimePrecision` (default 1s): `exp 100.9 -> 100` | RFC 7519 §2 explicitly permits non-integer NumericDate. Keyorix never changes `TimePrecision`, so sub-second precision is dropped consistently. **Impact: none** — a fractional second never changes an expiry verdict at 1s granularity. |
| `reject` | not a finite-float JSON number (`"123"`, `true`, `null`-as-value, `1e400`, `{}`) | `UnmarshalJSON` returns an error → the whole `ParseWithClaims` fails → token rejected | AGREEMENT: the strict reference rejects too. Keyorix rejects the token. |

## Known non-reachable quirk (documented, not exercised)

golang-jwt's `NumericDate.MarshalJSON` mishandles a NEGATIVE fractional time at
sub-second `TimePrecision`: it concatenates the integer seconds string with the
fractional string (`"-1"` + `".5"` → `"-1.5"`), which is `-1.5s`, not the intended
`-0.5s`. This only manifests when `TimePrecision < time.Second`. Keyorix leaves
`TimePrecision` at its 1-second default (where the fractional part is formatted to
zero digits and dropped), so the quirk is unreachable here. Recorded so a future
change to `TimePrecision` re-opens this as a live concern.

## Directions that FAIL (NEW classes, not in this table)

- **`exact-int` mismatch** — golang-jwt decoded an integer `\|v\| <= 2^53` to the
  wrong number of Unix seconds. A real round-trip/correctness defect on the live
  expiry path.
- **accept-parity mismatch** — golang-jwt accepted a value the strict reference
  rejected (or vice versa) outside the classes above. Would mean the two disagree
  on what is even a valid NumericDate.
