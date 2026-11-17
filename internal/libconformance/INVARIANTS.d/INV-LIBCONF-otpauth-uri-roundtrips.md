- **INV-LIBCONF-otpauth-uri-roundtrips** The otpauth:// URI that `totp.Generate`
  returns at MFA enrolment re-parses to the same issuer, account name (any username,
  including legacy ones the charset rule would refuse today), secret, period, digits and
  algorithm, carries each parameter once, and the re-parsed key computes the same codes.
  Two known pquerna/otp limits (an issuer holding ':' or '&'/'+') are modelled exactly
  and do not apply to keyorix's constant issuer. Why: the authenticator's reading of the
  URI and keyorix's code check must agree, or enrolment silently binds a different
  secret or account. Guard:
  `internal/libconformance/otp_totp_fuzz_test.go:FuzzTOTPDifferential`,
  `internal/libconformance/otp_findings_test.go:TestOTPKeyorixShapeRoundTrips`.
<!-- section: MFA (TOTP) -->
