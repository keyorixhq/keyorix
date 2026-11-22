- **INV-ENCRYPTION-file-kek-read-wiped** For the "file" key provider with a raw, hex, base64 or
  URL-safe base64 KEK file, no copy of the KEK (raw bytes or its hex/base64 text) allocated under
  `crypto.(*FileKeyProvider).KEK` is found in readable process memory after one first-boot
  `Initialize` + `Shutdown` on Linux. `FileKeyProvider.KEK` wipes `io.ReadAll`'s buffer when it
  holds encoded text, `decodeKeyMaterial` decodes from the `[]byte` (no immutable string copy) and
  wipes each scratch buffer it does not return, and the returned KEK is `KeyManager.Initialize`'s
  `kek` (`defer wipeBytes`). Why: #4498 (the encoded text was left in the read buffer and in a
  `string` copy). Guard: `internal/encryption/memresidue_test.go`:
  `TestKeyMaterialAbsentFromProcessMemoryAfterShutdown/site-claims` (long lane:
  `KEYORIX_MEMRESIDUE_ORACLE=1`, Linux with a readable `/proc/self/mem`): the attribution child
  runs with the GC off, so a copy is absent because it was wiped, not because its memory was
  reused; it also fails if `FileKeyProvider.KEK` appears in no sampled allocation stack (a renamed
  function cannot pass vacuously). Format contract: `internal/crypto/raw_providers_wipe_test.go`
  (default lane). **Not covered**: KEK files larger than `io.ReadAll`'s first 512-byte buffer (a
  grown buffer leaves its predecessor unwiped), upper-case hex text, the env and exec providers
  (they also call `decodeKeyMaterial` but are not scanned), and the encoded file in the kernel's
  page cache; the same lane as INV-ENCRYPTION-memresidue-ratchet, which no CI job runs yet.
<!-- section: Memory hygiene -->
