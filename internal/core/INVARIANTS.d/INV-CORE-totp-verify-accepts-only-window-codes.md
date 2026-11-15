- **INV-CORE-totp-verify-accepts-only-window-codes** The MFA TOTP verify path
  (`validateTOTPStep`, `internal/core/mfa.go`) accepts a user-supplied code only if it
  equals the code `github.com/pquerna/otp` generates for the current 30-second step or the
  step immediately before/after it (SHA-1, 6 digits, `Skew=0` generation with a manual ±1
  check and a constant-time compare). A code that matches no code in that three-step window
  is rejected; the library's RFC 4226 (HOTP) and RFC 6238 (TOTP, SHA-1/256/512) answers are
  exactly what `pquerna/otp` produces. Why: a verifier that accepts a non-window code lets a
  wrong one-time password authenticate — the whole point of the MFA second factor. The repo
  had no conformance or mutation coverage of this library/call-path before WV1.
  Guard: `internal/libconformance` lib-contract targets `TestHOTP_RFC4226_KnownAnswers`,
  `TestTOTP_RFC6238_KnownAnswers` (pin the RFC vectors against `pquerna/otp`) and
  `FuzzTOTPMutation` (fail-closed: a one-digit mutation of a valid code that is not itself a
  window code must be rejected; red/green-proved by widening the verifier window).
  **Not covered**: the single-use enforcement of a consumed step (`MarkTOTPStepUsed`), the
  encryption-at-rest of the TOTP seed (that is `internal/encryption`'s AAD binding,
  INV-ENCRYPTION MFA-AAD), replay across the ±1 window within a step's validity, and the
  unexported `validateTOTPStep` wrapper itself — the guard exercises the library at
  keyorix's exact configuration, not keyorix's own function, to keep the fuzz coverage map
  on the `pquerna/otp` leaf (see `internal/libconformance/doc.go`).
