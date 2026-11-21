- **INV-FUZZJWT-claims-codec** The golang-jwt/jwt/v5 (v5.3.1) claims codec —
  `jwt.NumericDate.UnmarshalJSON`/`MarshalJSON` (for `exp`/`nbf`/`iat`) and
  `jwt.ClaimStrings.UnmarshalJSON`/`MarshalJSON` (for `aud`) — decoded through the
  EXACT shape both live Keyorix verify paths use (a struct embedding
  `jwt.RegisteredClaims`, the `liveClaims` mirror here): (a) never panics or hangs
  on arbitrary payload JSON (`fuzzutil.Guard`); (b) allocates at most `64 KiB +
  512·len` decoding the claims struct (order-of-magnitude amplification detector);
  (c) is round-trip idempotent to a FIXED POINT — if the bytes decode,
  `marshal→unmarshal→marshal` is byte-stable, so the codec can always re-ingest its
  own output; and (d) an integer `exp`/`nbf`/`iat` value exactly representable in
  `float64` (`|v| <= 2^53`) decodes to precisely that many Unix seconds (a drift
  would silently move a token's expiry). Why: golang-jwt decodes the payload JSON
  into `RegisteredClaims` — invoking these custom unmarshalers — BEFORE it verifies
  the signature, so every byte of `exp`/`nbf`/`iat`/`aud` is attacker-controlled and
  reaches the codec pre-authentication on `internal/oidcverify
  OIDCVerifier.VerifyWithExpiry` and `internal/core KeyorixCore.verifyIDToken`. No
  other fuzz target exercises this codec: `FuzzOIDCVerifierClaims` builds
  `jwt.MapClaims` programmatically (the `Validator`, not these decoders) and
  `FuzzJWTDifferential` parses into `jwt.MapClaims` with `ParseUnverified`. Each
  oracle carries a RED/GREEN proof built in-test (no production code modified):
  `TestClaimsCodec_GuardMechanism` (Guard fires on an over-budget closure, stays
  silent on a fast one), `TestClaimsRoundTrip_RedProof` (the fixed-point check
  fires when `aud` is dropped), `TestNumericDateDifferential_RedProof` (the
  exact-int check fires on a ±1s perturbation). Non-exact NumericDate classes
  (float-precision, overflow, fractional) and the aud string-vs-array family are
  pinned by `TestNumericDate_HugeExpIsFailClosed` and `TestClaimStrings_AudForms`
  and documented in `EXPECTED-DIFFERENCE-NUMERICDATE.md`. Guard:
  `FuzzJWTClaimsCodec`, `FuzzNumericDateDifferential`,
  `TestClaimsCodec_GuardMechanism`, `TestClaimsRoundTrip_RedProof`,
  `TestNumericDateDifferential_RedProof`, `TestNumericDate_HugeExpIsFailClosed`,
  `TestClaimStrings_AudForms` (`fuzz/thirdparty/jwt`).
