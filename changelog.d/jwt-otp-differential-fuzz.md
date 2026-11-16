### Testing
- **Differential + bounded-work fuzz harnesses for the token libraries Keyorix
  authenticates with (`golang-jwt/jwt/v5`, `pquerna/otp`).** New `fuzz/thirdparty/jwt`
  and `fuzz/thirdparty/otp` packages. The JWT harness differentially compares
  golang-jwt's structural parse against an in-harness strict RFC 7519/7515/8725
  reference decoder (no second JWT implementation is in the module cache), pins the
  asymmetric-only alg-confusion posture of the two live verify paths
  (`internal/oidcverify`, SSO login) with red proofs, and guards against the
  header memory-exhaustion CVE class (CVE-2025-30204). The OTP harness pins the
  RFC 4226 (SHA1, 6 digits) and RFC 6238 (8 digits) vectors, round-trips `otpauth://`
  URLs, and documents base32-secret leniency versus a strict decoder. Disagreement
  classes are enumerated in committed `EXPECTED-DIFFERENCE.md` tables so only a NEW
  class fails. No production code changed.
