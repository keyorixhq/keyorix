- **INV-ENCRYPTION-auth-ops-refuse-when-disabled** `admin encryption auth-encryption`
  enable (with or without `--force`), rotate, migrate and validate refuse while
  `storage.encryption.enabled` is false, before opening the database. `AuthEncryption`
  passes bytes through unchanged when encryption is disabled, so without this migrate
  wrote plaintext into `encrypted_token` and reported it migrated, validate reported
  every check passed, and enable `--force` reported (and audited) an enablement that
  never happened. They also return the passphrase resolver's error instead of
  discarding it. Why: REVIEW-ENCRYPTIONOPS-1 F1/F2. Guard:
  `internal/encryptionops/review_encryptionops_auth_test.go`
  (`TestAuthEncryptionCommands_EncryptionDisabled_RefuseWithoutTouchingRows`,
  `TestAuthEncryptionCommands_PassphraseSourceErrorIsReported`). **Not covered**: `status`,
  which is read-only and reports DISABLED.
