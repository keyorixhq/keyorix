### Testing
- **golang-jwt/jwt/v5 claims-codec fuzzing (JO1).** Added `FuzzJWTClaimsCodec` and
  `FuzzNumericDateDifferential` to `fuzz/thirdparty/jwt`, covering the previously
  unfuzzed `jwt.NumericDate`/`jwt.ClaimStrings` JSON codec that both live verify
  paths (`internal/oidcverify OIDCVerifier.VerifyWithExpiry`,
  `internal/core KeyorixCore.verifyIDToken`) invoke when decoding a token payload
  into `jwt.RegisteredClaims` before the signature is checked. Oracles: no
  panic/hang, bounded allocation, round-trip idempotence to a fixed point, and an
  exact Unix-seconds differential for integer `exp`/`nbf`/`iat` values (with a
  committed EXPECTED-DIFFERENCE table for float-precision/overflow/fractional
  classes). Each oracle carries an in-test red/green proof; no production code
  changed. `go-jose` is not a dependency of this repo — this extends the nearest
  reachable JOSE-family surface instead. Guarded by `INV-FUZZJWT-claims-codec`.
