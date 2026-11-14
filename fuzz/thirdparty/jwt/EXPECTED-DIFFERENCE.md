# EXPECTED-DIFFERENCE table — golang-jwt/jwt/v5 vs strict RFC 7519/7515/8725

`FuzzJWTDifferential` compares golang-jwt's structural parse (`ParseUnverified`,
configured with Keyorix's real `WithValidMethods` asymmetric allowlist) against a
strict RFC reference decoder on the SAME bytes. The reference decoder is
deliberately STRICTER than golang-jwt. Every place golang-jwt (and therefore
Keyorix) is more lenient than a strict RFC 8725 reading is a NAMED class below;
the fuzzer fails ONLY on a disagreement outside this table (a NEW class).

Each row is keyed by the reason code in `hostile_jwt_test.go`.

| Class (reason code) | golang-jwt | strict RFC | Why it is expected / Keyorix impact |
|---|---|---|---|
| `b64-noncanonical` | accepts | rejects | Go's `base64.RawURLEncoding` (no `.Strict()`) ignores non-zero trailing bits. golang-jwt only tightens this with `WithStrictDecoding`, which Keyorix does NOT set. **Impact: none** — the bytes still decode to the same header/claims; a signature over non-canonical base64 still must verify. Talk-worthy: Keyorix inherits this leniency. |
| `header-dup` / `payload-dup` | accepts (last wins) | rejects | `encoding/json` silently keeps the last of duplicate member names; RFC 8725 §2.1 says reject. **Impact: low** — a `{"alg":"RS256","alg":"none"}` style split-brain header is possible at the byte level, but golang-jwt's `token.Method` is taken from the last `alg` and `WithValidMethods` still rejects a non-allowlisted final value. Keyorix's `crit` check and claim policy read the unmarshalled (last-wins) map, consistently. |
| `alg-missing` | accepts in `ParseUnverified` | rejects | `ParseUnverified` does not require a resolvable `alg`; verification (`Parse`) does. Keyorix always calls `Parse`/`ParseWithClaims`, where a missing/unknown `alg` fails method selection. |
| `alg-none` | accepts in `ParseUnverified` | rejects | Same: `ParseUnverified` does not enforce the allowlist. Keyorix's `WithValidMethods` rejects `none` at verification (see `TestAlgConfusion_NoneRejected`). |
| `alg-not-allowed` | accepts in `ParseUnverified` | rejects | Same; HS256 and any non-asymmetric alg are rejected at verification by Keyorix's allowlist (`TestAlgConfusion_HS256WithRSAPublicKeyRejected`). |
| `crit` | accepts in `ParseUnverified` | rejects | `ParseUnverified` never inspects `crit`. Keyorix rejects ANY `crit` header AFTER parse (oidc.go:196, sso.go:1432) because it understands no extensions (RFC 7515 §4.1.11). |
| `exp-type` / `nbf-type` / `iat-type` | accepts in `ParseUnverified` | rejects | `ParseUnverified` does not type-check numeric-date claims. At verification golang-jwt's `NumericDate` unmarshal rejects a non-number `exp`; Keyorix sets `WithExpirationRequired`, so a bad `exp` fails. |
| `aud-type` | accepts in `ParseUnverified` | rejects | Same: aud typing is a claim-validation concern, not a structural one. Keyorix's `ClaimStrings` unmarshal rejects an `aud` that is neither string nor string array. |

## Directions that FAIL (NEW classes, not in this table)

- **strict ACCEPTED but golang-jwt rejected** — golang-jwt stricter than a strict RFC
  reading. The one instance found during harness bring-up was the harness's own
  gap (golang-jwt base64-decodes the signature segment, which the reference decoder
  initially skipped) — fixed in the reference decoder, recorded as ARTIFACT, seed
  `testdata/fuzz/FuzzJWTDifferential/dba2a91d89fa98ed`. A genuine such case would be
  a real finding.
- **golang-jwt ACCEPTED, strict rejected on an agreement-level reason**
  (`segments`, `b64-invalid`, `header-json`, `payload-json`) — would mean the two
  disagree on a check they are supposed to share. None found.
