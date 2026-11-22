- **INV-ENCRYPTION-memresidue-ratchet** What the memory-residue oracle measures, for one
  first-boot `Initialize` + `Shutdown` on Linux in each scenario (the "file" key provider with a
  raw, hex, base64 and URL-safe base64 KEK file, and the passphrase provider): the raw DEK is not
  found at `EncryptionService.dek`'s address after `Shutdown` (INV-ENCRYPTION-24), and the number
  of other copies of the raw DEK, the raw KEK, the KEK's hex/base64/URL-safe base64 text and the
  master passphrase found anywhere in readable process memory does not exceed
  `memResidueRatchet[scenario][kind]` (a bound that only goes down). Every raw DEK/KEK copy counted
  today is attributed to state inside Go's crypto packages (AES key schedules, GCM block copies,
  the SHA-256 buffer of HKDF's HMAC), which application code cannot zero; the counted passphrase
  copies are the immutable string `Service.Initialize` receives and the password copies inside
  `x/crypto/pbkdf2` and Go's `crypto/pbkdf2`. This is not a claim that no key bytes remain in
  memory. Why: #4498. Guard: `internal/encryption/memresidue_test.go`:
  `TestKeyMaterialAbsentFromProcessMemoryAfterShutdown` (long lane: `KEYORIX_MEMRESIDUE_ORACLE=1`,
  not `-short`, Linux with a readable `/proc/self/mem`; skips elsewhere), with a live control (the
  claimed copy and a raw KEK copy are found before `Shutdown`) and a red control (zeroing only
  the claimed copy removes exactly its hits); verdict rules: `memresidue_verdict_test.go`
  (`TestMemResidueVerdict`, `TestMemResidueSiteVerdict`; default lane, every platform).
  Attribution: `memresidue_attribute_linux_test.go:TestMemResidueAttribute` (opt-in,
  `KEYORIX_MEMRESIDUE_ATTRIBUTE=1`).
  **Not covered**: no CI lane sets `KEYORIX_MEMRESIDUE_ORACLE` yet (the scan runs only when
  someone runs it by hand); swap, core files and the kernel; other key providers (env, exec, KMS,
  TPM, Shamir); upper-case hex; rotation, rewrap and KEK-derived keys; macOS.
<!-- section: Memory hygiene -->
