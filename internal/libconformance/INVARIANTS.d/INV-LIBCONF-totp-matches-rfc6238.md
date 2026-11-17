- **INV-LIBCONF-totp-matches-rfc6238** pquerna/otp's `totp.GenerateCodeCustom` (what
  `internal/core/mfa.go` uses for every MFA login and step-up) equals an independent
  RFC 4226/6238 implementation for every secret spelling, time below 2^53 s, period,
  digit count and algorithm, and `ValidateCustom` agrees with it; the reference itself
  reproduces the RFC 6238 Appendix B vectors. Why: a code computation that drifts from
  the RFC locks users out or, worse, accepts codes their authenticator never showed.
  Guard: `internal/libconformance/otp_totp_fuzz_test.go:FuzzTOTPDifferential`,
  `internal/libconformance/otp_findings_test.go:TestRFC6238Vectors`.
<!-- section: MFA (TOTP) -->
