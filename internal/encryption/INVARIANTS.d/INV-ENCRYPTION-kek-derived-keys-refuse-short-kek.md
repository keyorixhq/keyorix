- **INV-ENCRYPTION-kek-derived-keys-refuse-short-kek** Every KEK-derived HKDF key
  (`deriveEvidenceSignKey`, `deriveAuditCheckpointKey`, `auditverify.DeriveBackupManifestKey`)
  calls `auditverify.CheckKEKLen` first and refuses a KEK shorter than `MinKEKLen` (14 bytes,
  112 bits) with a typed `*KEKTooShortError` (`errors.Is(err, ErrKEKTooShort)`) and no key
  material, identically in every Go FIPS mode. Callers propagate the error and fail closed: no
  evidence-signing, checkpoint or manifest key is set, never a zero key. Valid KEKs derive
  byte-identical keys to the pre-guard code, so no stored checkpoint or evidence signature
  changes. A new KEK-derived HKDF key must call `CheckKEKLen` too. Why: under
  `GODEBUG=fips140=only` crypto/hkdf panics on a sub-112-bit key (FIPS-TAILS-1 item 1).
  Guard: `internal/encryption/kek_min_len_test.go`: `TestKEKDerivation_ShortKEKRefusedValidKEKGolden`
  (0/1/13-byte KEKs refused, 14/32-byte golden vectors) and `TestInitialize_ShortKEKProvider_FailsClosed`.
  **Not covered**: a new derivation that skips `CheckKEKLen` is not detected unless it is added
  to the test's `kekDerivations` table.
