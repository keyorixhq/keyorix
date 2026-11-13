- **INV-BACKUPFMT-corrupt-restore-fail-closed** A corrupted or mutated old-release archive
  must fail closed and leave NO partial state. Two layers enforce it: (1) `ExtractArchive`
  refuses any gzip/tar damage, per-entry sha256 mismatch or structural violation before a
  single row is loaded; (2) `LoadArchive` runs inside one transaction, so a load that fails
  (schema-delta refusal, row-count mismatch, dangling reference) rolls back and leaves every
  load-bearing table empty, and a load that *succeeds* on an accepted mutation reproduces
  exactly the pristine archive's restored content — never a silently-altered one. At the full
  `admin restore` command level the same corruption additionally writes no database and no key
  material (`dek.key`/`kek.salt`). Why: task I6; restore is operator-supplied, untrusted input
  that may come from removable media. Guard: `FuzzI6OldArchiveMutation`
  (`internal/backupfmt/i6_oldarchive_fuzz_test.go`: seeded with the real v0.96.3 archive,
  asserts extract-refuse / load-rollback-empty / successful-load-equals-baseline on every
  mutation) and `TestI6RestoreOldVersion_CorruptFailsClosed`
  (`server/admin`: full command, seven corruption shapes, asserts no database and no key
  material written; six are refused at extraction, and `manifest-tamper` (a well-packed archive
  with one signed manifest byte changed) gets past extraction and KEK unwrap and is refused by
  the manifest-signature gate).
  **Not covered by FuzzI6OldArchiveMutation**: the HMAC manifest-signature gate
  (`VerifyManifestSignature`, covered by `manifest_sign_fuzz_test.go`) and the per-exec 64 KiB
  / 2000-row harness caps mean row-count/decompression amplification shapes are bounded out,
  not asserted as product behaviour (operator caps `restoreMaxEntryBytes`/`restoreMaxTotalBytes`
  are fuzzed by `FuzzExtractArchive`).
