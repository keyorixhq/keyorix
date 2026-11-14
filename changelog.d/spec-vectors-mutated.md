### Testing
- **Known-answer conformance + mutation fuzzing for the TOTP and age library contracts
  keyorix's MFA and recovery-key paths depend on.** New `internal/libconformance`
  lib-contract targets: `TestHOTP_RFC4226_KnownAnswers` / `TestTOTP_RFC6238_KnownAnswers`
  pin `github.com/pquerna/otp` to the RFC 4226 / RFC 6238 vectors (SHA-1/256/512), and
  `FuzzTOTPMutation` asserts that — with the verifier configured as `internal/core/mfa.go`
  configures it — a one-digit mutation of a valid code that is not itself a ±1-step window
  code is always rejected. `TestAge_KnownAnswerVector` decrypts the upstream `filippo.io/age`
  test vector to its known plaintext, and `FuzzAgeCiphertextMutation` asserts that no
  single-bit flip of a valid `age` ciphertext (recovery-key encryption,
  `server/admin/recovery_key_encrypt.go`) ever decrypts to different plaintext, including
  across the >64 KiB STREAM chunk boundary. Both oracles are red/green-proved. Guarded by
  INV-CORE-totp-verify-accepts-only-window-codes and
  INV-ADMIN-recovery-key-age-ciphertext-is-tamper-evident.
