# What we observed under `GODEBUG=fips140=only`

This note records what we saw when the test suites ran under Go's strictest FIPS
140-3 setting, `GODEBUG=fips140=only`. In that mode the Go crypto module refuses
any non-approved algorithm or parameter, usually by panicking. **This is not a
FIPS 140-3 compliance or validation claim** for Keyorix, its build or any
deployment. It is a list of refusals seen on one date at one commit, and an open
list of work.

- **Observed:** 2026-10-31, Go 1.27.3 darwin/arm64, at commit `4f9636f55`
  (branch `fips-tails-1/kek-selftest-sweep`, based on `edc8f0c5b`, which
  includes #3833). Packages `internal/encryption/...` and `internal/crypto/...`
  were swept at `23d9f7f20`, `internal/auditverify` at `924532884` and `server/admin` at `a2bf81780`.
- **Method:** `GODEBUG=fips140=only go test -count=1` for each package, one
  package at a time. Each panic aborts its test binary, so the panicking test
  was skipped and the rest re-run until no panic was left. Every refusal and
  every plain failure was recorded. Each non-panic failure was then re-run alone
  in both modes, to separate FIPS refusals from test-isolation artefacts.
- **Packages:** `internal/encryption/...`, `internal/crypto/...`,
  `internal/auditverify` and `server/admin` (both touched by this work),
  `internal/storage/...`, `server/http/...`, `server`, `internal/core`.
- **Clean:** `internal/encryption`, `internal/encryption/aead`,
  `internal/crypto`, `internal/crypto/gcpkms`, `internal/storage`,
  `internal/storage/models`, `internal/storage/sqlitedialect`,
  `internal/storage/store`, and the `server/http/handlers` sub-packages
  `contracttest`, `httpx`, `reports` and `webauthnparse`.

## Refusals

| # | Package (tests affected) | Test(s) | Primitive refused | Where | Production or test-only | Status |
|---|---|---|---|---|---|---|
| 1 | internal/encryption, internal/auditverify | `TestDeriveEvidenceSignKey_EmptyKEK`, `TestDeriveAuditCheckpointKey_EmptyVsZeroKEK` (before the fix) | HKDF with a key under 112 bits | `deriveEvidenceSignKey`, `deriveAuditCheckpointKey`, `auditverify.DeriveBackupManifestKey` | Production (latent: providers and the AES key-size check refuse a short KEK earlier on the boot path) | **Fixed** (FIPS-TAILS-1 item 1): typed `KEKTooShortError` in both modes |
| 2 | internal/core (112), server/http/handlers (53), server/http (6) | Every test that enrols or verifies a TOTP code, e.g. `TestMFAFailed_IsStoredWithSuccessFalse`, `TestAccountSetup_EitherOrder_EndsInMFALogin`, the `login_lockout_no_oracle`, `mfa_stepup_handler` and `login_identity_fail_closed` families | HMAC-SHA-1 (`crypto/hmac`: hash other than SHA-2/SHA-3) | `internal/core/mfa.go` `validateTOTPStep` → `pquerna/otp` `totp.GenerateCodeCustom(..., AlgorithmSHA1)`. A direct call panics under fips140=only, and the test helpers that generate codes hit the same panic first | **Production**: TOTP login, step-up and activation panic under fips140=only | **Open**, needs a product decision (see "Open items") |
| 3 | server (2), server/admin (2) | `TestAdminRecoveryKey_RotateWithRecipient_EncryptedOutputOnly`, `TestAdminRecoveryKey_OutputAlreadyExists_LeavesOldKeyValid`, `TestParseRecoveryKeyRecipient_AgeString`, `TestParseRecoveryKeyRecipient_SSHEd25519File` (`crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode`) | X25519 (an age recipient is refused as "invalid X25519 public key") | `keyorix-server admin recovery-key rotate --recipient` (age encryption of the recovery key) | **Production** (admin command, not the serving path) | **Open** |
| 4 | internal/crypto/azurekms (4) | `TestAzureKMS_EncryptPinsVersionAndSurvivesRotation`, `TestAzureKMS_EncryptDecryptRoundTrip`, `TestDecrypt_PinnedEnvelopeWithWrongMACRefused`, `TestDecrypt_UnwrapKeyError_PinnedEnvelope` | HMAC with a key under 112 bits | Fixture: a stand-in KEK of 3 or 7 bytes keys the envelope MAC (`versionMAC`) | Test-only fixture. Related production gap: see open item 4 | Skipped under `fips140.Enforced()`, reason given |
| 5 | internal/crypto/awskms (1) | `TestNew_SuccessResolvesKeyThroughEndpoint` | HMAC with a key under 112 bits | Fixture: `AWS_SECRET_ACCESS_KEY="secret"`, so the SigV4 HMAC key is `"AWS4secret"` (10 bytes). Real AWS secret keys are 40 characters | Test-only | Skipped under `fips140.Enforced()`, reason given |
| 6 | server/http/handlers (1) | `TestCompleteSAML_TraversalLimit` | SHA-1 (`crypto/sha1`) | Fixture: samltest's IdP builds its POST-binding response with SHA-1 | Test-only (an IdP signing with SHA-1 is refused under fips140=only, as it should be) | Skipped under `fips140.Enforced()`, reason given |
| 7 | internal/core (2) | `TestOIDCVerify_Rejections/HMAC_algorithm_rejected`, `FuzzVerifyIDToken` (HS256 seed) | HMAC with a key under 112 bits | Fixture: an HS256 token forged with a 6-byte secret. The verifier's method allowlist rejects HS256 before any HMAC is computed | Test-only | Subtest skipped and seed left out under `fips140.Enforced()`, reason given |
| 8 | internal/auditverify (5) | `TestVerify_NoKeyNeverAuthenticatesARetentionAnchor`, `TestVerify_ExternalAnchorAuthentication`, `TestParseRetentionAnchorValue_V2RoundTrip`, `TestParseRetentionAnchorValue_V1IsPurgedZero`, `TestParseRetentionAnchorValue_LayoutsDomainSeparated` | HMAC with a key under 112 bits | Fixture: checkpoints and retention anchors signed with a nil or 1-byte key | Test-only. Related production gap: see open item 5 | Skipped under `fips140.Enforced()`, reason given |
| 9 | server/admin (4) | `TestParseRecoveryKeyRecipient_HybridRoundTrip`, `TestParseRecoveryKeyRecipient_MalformedHybridRefused`, `TestWarnIfClassicalRecoveryKeyRecipient`; `TestRunAdminValidatePosture_StartupValidationGolden` | X25519 in the fixture's `age.GenerateHybridIdentity`, which never returned (10-minute test timeout); the golden files record the default-mode FIPS lines | Test-only (the fixture generates keys; production only parses recipients, see row 3) | Skipped under `fips140.Enforced()`, reason given |

Isolation artefacts, not FIPS refusals: `TestCreateUserLegacy_ValidationError_S19`
and `TestCreateUser_NilHandler` (server/http/handlers) panic with "i18n not
initialized" when run alone, in both modes. They depend on an earlier test
initialising i18n.

## Open items (production, not fixed here)

1. **TOTP is HMAC-SHA-1** (row 2). RFC 6238 TOTP with SHA-1 is what nearly every
   authenticator app supports. Under fips140=only, every TOTP verification
   panics. The options are product decisions. Offering SHA-256 TOTP for new
   enrolments breaks apps that ignore the `algorithm` parameter. Refusing TOTP
   in that mode, with a clear error instead of a panic, leaves WebAuthn as the
   only MFA. A smaller step that could go first: return an error instead of
   panicking when `fips140.Enforced()`.
2. **The recovery-key `--recipient` path uses age (X25519)** (row 3). The
   options are a FIPS-approved recipient type, or refusing `--recipient` with a
   clear error under fips140=only.
3. **The webhook signing secret has no minimum length** (found by reading the
   code; the swept packages do not cover it). `internal/notifychan/webhook.go`
   keys HMAC-SHA256 with the operator's `SigningSecret`. A secret under 14 bytes
   panics on delivery under fips140=only. Proposed: refuse it at configuration
   time, or fail the send with an error.
4. **Azure KMS unwrap result length** (behind row 4).
   `internal/crypto/azurekms` `Decrypt` keys `versionMAC` with the unwrapped
   plaintext without checking its length first. A Key Vault response, or a
   component in front of it, returning fewer than 14 bytes panics under
   fips140=only instead of being refused. Proposed: check `len(res.Result) ==
   crypto.KEKSize` before `versionMAC`.
5. **An operator-supplied audit checkpoint key under 14 bytes** (behind row 8,
   found by reading the code). `internal/auditverify` skips authentication when
   no key is given, but a non-empty key shorter than 14 bytes reaches
   `hmac.New` and panics under fips140=only, instead of being reported as not
   authenticated. Proposed: treat a key under `auditverify.MinKEKLen` as a usage
   error.

The boot self-test (`encryption.BootFIPSSelfTest`,
INV-ENCRYPTION-fips140-boot-self-test) covers the AEAD and KEK-derived-key paths
only. It passes under fips140=only, and a server with no TOTP users boots and
serves in that mode. The items above sit outside those paths.
