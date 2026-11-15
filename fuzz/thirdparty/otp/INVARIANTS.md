# fuzz/thirdparty/otp invariants

Read this before changing the pquerna/otp (HOTP/TOTP) conformance + fuzz harness. This
package is test-only (`otphostile`). It pins the library behaviour the live Keyorix MFA
paths depend on: enrolment (`internal/core/mfa.go:126` `totp.Generate`) and
activation/login/step-up (`internal/core KeyorixCore.validateTOTPStep` `totp.GenerateCodeCustom` via
`validateTOTPStep`, which rolls Keyorix's OWN ±1-step window at Period=30/Digits=6/SHA1).
If those callers' options change, update the mirror here in the same change.

Format: `INV-FUZZOTP-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-FUZZOTP-<kebab-slug>.md` (one per file).

## Oracles
