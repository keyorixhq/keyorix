- **INV-ENCRYPTION-memresidue-ratchet** What the memory-residue oracle measures, for one
  first-boot `Initialize` + `Shutdown` with the "file" key provider on Linux: the raw DEK is not
  found at `EncryptionService.dek`'s address after `Shutdown` (INV-ENCRYPTION-24), and the number
  of other raw DEK / KEK copies found anywhere in readable process memory does not exceed
  `memResidueRatchet` (a bound that only goes down). Every copy counted today is attributed to
  state inside Go's crypto packages (AES key schedules, GCM block copies, the SHA-256 buffer of
  HKDF's HMAC), which application code cannot zero; this is not a claim that no key bytes remain
  in memory. Why: #4498. Guard: `internal/encryption/memresidue_test.go`:
  `TestKeyMaterialAbsentFromProcessMemoryAfterShutdown` (long lane: `KEYORIX_MEMRESIDUE_ORACLE=1`,
  not `-short`, Linux with a readable `/proc/self/mem`; skips elsewhere), with a live control (the
  claimed copy is found before `Shutdown`) and a red control (zeroing only that copy removes
  exactly its hits); verdict rules: `memresidue_verdict_test.go:TestMemResidueVerdict` (default
  lane, every platform). Attribution: `memresidue_attribute_linux_test.go:TestMemResidueAttribute`
  (opt-in, `KEYORIX_MEMRESIDUE_ATTRIBUTE=1`).
  **Not covered**: no CI lane sets `KEYORIX_MEMRESIDUE_ORACLE` yet (the scan runs only when
  someone runs it by hand); swap, core files and the kernel; other key providers (passphrase,
  env, KMS, TPM, Shamir), hex/base64-encoded KEK files (the oracle looks for raw bytes only);
  rotation, rewrap and KEK-derived keys; macOS.
<!-- section: Memory hygiene -->
