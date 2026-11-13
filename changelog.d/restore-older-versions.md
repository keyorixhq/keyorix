### Testing
- **Old-release backup restore is now proven against what real released binaries wrote.**
  A fixture generator (`scripts/i6-gen`) runs a released tag's own `admin backup` to emit a
  v2 logical archive plus an old-code canonical sidecar; `TestI6RestoreOldVersion`
  (`server/admin`) restores the v0.96.3 fixture into current `main` on SQLite and PostgreSQL
  and asserts every secret decrypts to its original plaintext, the audit chain verifies VALID,
  roles/grants/counts equal the source, and a re-backup round-trips again.
  `TestI6RestoreOldVersion_CorruptFailsClosed` and the new `FuzzI6OldArchiveMutation`
  (`internal/backupfmt`, seeded with the real old-release archive) assert a corrupted or mutated
  archive fails closed and leaves no partial state (no half-restored database, no key material
  written). New invariants `INV-BACKUPFMT-oldrelease-restore-lossless` and
  `INV-BACKUPFMT-corrupt-restore-fail-closed`.
