- **INV-FUZZJWT-asymmetric-only** A parser configuration MIRRORED from the live Keyorix
  callers (a copy in `keyorixParser`, not the production parser, so this cannot detect a
  production allowlist change; production is covered by `internal/oidcverify/oidc_fuzz_test.go`
  and `internal/core/jwt_cross_verifier_differential_test.go`) rejects every non-asymmetric or out-of-allowlist signing method: `alg=none`, an
  HS256 forgery that uses the RSA public key as the HMAC secret, an RS/PS method-vs-header
  mismatch, an EC curve mismatch, and a valid EdDSA token (EdDSA is deliberately NOT in the
  allowlist). `alg=none`, HS256 and EdDSA are each paired with a RED PROOF showing a
  deliberately-vulnerable local parser config accepts the same bytes; the RS-vs-PS and EC-curve
  cases have honest-token sanity checks instead of red proofs. Why: `WithValidMethods(RS/ES/PS
  256/384/512)` at `internal/oidcverify OIDCVerifier.VerifyWithExpiry` and `internal/core KeyorixCore.verifyIDToken` is the
  only thing standing between a leaked JWKS document and a forged token. Guard:
  `TestAlgConfusion_NoneRejected`, `TestAlgConfusion_HS256WithRSAPublicKeyRejected`,
  `TestAlgConfusion_RSvsPSRejected`, `TestAlgConfusion_ECCurveMismatchRejected`,
  `TestAlgConfusion_EdDSAOutsideAllowlistRejected` (`fuzz/thirdparty/jwt`).
