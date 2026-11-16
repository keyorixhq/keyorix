- **INV-FUZZOTP-rfc-vectors** pquerna/otp reproduces the published RFC 4226 Appendix D HOTP
  vectors (6-digit, SHA1) and the RFC 6238 Appendix B TOTP vectors (8-digit) for SHA1, SHA256
  and SHA512 exactly, and `hotp.Validate` accepts each published code. Why: these are the
  standard interop vectors; a dependency bump that silently altered the HMAC, dynamic
  truncation, or digit formatting would break Google-Authenticator interop for Keyorix MFA.
  A red proof (`TestRFC6238_OracleFiresOnWrongParams`) shows the vector check distinguishes
  algorithm and digit count. Guard: `TestRFC4226Vectors`, `TestRFC6238Vectors`,
  `TestRFC6238_OracleFiresOnWrongParams` (`fuzz/thirdparty/otp`).
