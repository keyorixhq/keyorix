- **INV-ENCRYPTION-gcm-nonce-drawn-by-aead** Every AES-GCM AEAD in internal/encryption's
  production code (the `aead.EncryptionService` and the key-file `wrapKey`/`unwrapKey`) is
  `cipher.NewGCMWithRandomNonce`: the nonce is drawn inside the crypto module, never supplied
  by the caller, so the paths keep working under `GODEBUG=fips140=only`. The stored layout is
  unchanged from the earlier `cipher.NewGCM` code (service: 12-byte nonce in metadata,
  ciphertext||tag in `Data`; key wrap: nonce(12)||ciphertext||tag(16)), in both directions.
  Why: FIPS-GCM-NONCE-1 (ENCRYPTION-HARDEN-1 item 3). Guard:
  `internal/encryption/gcm_compat_test.go`: `TestNoCallerSuppliedGCMNonce` (source scan),
  `TestGCM_FIPS140OnlyMode` (child process under fips140=only),
  `TestGCMCompat_LegacyVectorsOpen` (vectors written by the pre-change code) and
  `TestGCMCompat_NewOutputOpensUnderLegacyCode`.
  **Not covered**: the source scan does not see an aliased `crypto/cipher` import, and other
  packages (`cli/`, `internal/libconformance` tests) are out of its scope.
<!-- section: AEAD / AAD binding -->
