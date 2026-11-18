- **INV-ENCRYPTION-provider-blob-key-base** A tpm/*-kms provider's relative
  `wrapped_key_path` is written and read under the Service's key base
  (`Service.keyBaseDir`), the base `keyfiles.Registry`, `RequiredKeyFilePaths`,
  `ReconcileKeySet` and the key-file permission audit resolve it against, never
  under `KeyManager.baseDir` (the DEK's directory once an absolute `dek_path`
  is normalized). Only the password provider's salt joins the normalized base.
  Why: #4504 F1, an absolute `dek_path` booted once and then refused its own
  key set as incomplete. Guard: `provider_blob_base_test.go`
  (`TestBoot_KMSWrappedKeyPath_OneBaseForEveryKeyPathShape`, real
  `crypto.KMSKeyProvider` over an in-memory KMS client). **Not covered**: the
  TPM provider is not booted (no TPM simulator here); it takes the same
  `baseDir` argument from the same call.
