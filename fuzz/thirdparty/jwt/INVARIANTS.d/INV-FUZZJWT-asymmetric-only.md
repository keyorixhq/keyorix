- **INV-FUZZJWT-asymmetric-only** The parser configuration mirrored from the live Keyorix
  callers rejects every non-asymmetric or out-of-allowlist signing method: `alg=none`, an
  HS256 forgery that uses the RSA public key as the HMAC secret, an RS/PS method-vs-header
  mismatch, an EC curve mismatch, and a valid EdDSA token (EdDSA is deliberately NOT in the
  allowlist). Each is paired with a RED PROOF showing a deliberately-vulnerable local parser
  config accepts the same bytes, so the guard is not vacuous. Why: `WithValidMethods(RS/ES/PS
  256/384/512)` at `internal/oidcverify/oidc.go:152` and `internal/core/sso.go:1391` is the
  only thing standing between a leaked JWKS document and a forged token. Guard:
  `TestAlgConfusion_NoneRejected`, `TestAlgConfusion_HS256WithRSAPublicKeyRejected`,
  `TestAlgConfusion_RSvsPSRejected`, `TestAlgConfusion_ECCurveMismatchRejected`,
  `TestAlgConfusion_EdDSAOutsideAllowlistRejected` (`fuzz/thirdparty/jwt`).
