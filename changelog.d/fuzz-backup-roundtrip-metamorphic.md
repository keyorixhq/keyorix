### Testing

- **Metamorphic backup/restore round-trip fuzzer.** New `FuzzBackupRestoreRoundTrip`
  (`server/admin`) drives a bounded, fuzz-byte-driven sequence of real core mutations
  (projects, secrets, versions, roles, machine identities, deletes) onto a seeded,
  encrypted store, then exercises the ordinary `admin backup` → `admin restore`
  (fresh-dir, real startup path) → re-backup cycle on the resulting arbitrary state and
  asserts six oracles: logical-state equality `restore(backup(S)) == S` (minus documented
  exclusions), every secret version still decrypts to its original plaintext under the
  restored key files, the restore's verify-audit reports VALID, idempotence
  `backup(restore(backup(S))) == backup(S)`, and that any refusal is an explicit error
  rather than silent corruption. Runs on SQLite always and on PostgreSQL when
  `KEYORIX_TEST_PG_DSN` is set (isolated `bk_<pid>_<n>` databases, dropped on cleanup).
  Complements the malformed-archive reader fuzzers and the crash-point/killed-rotation
  tests, which never fuzzed the ordinary cycle on arbitrary states. Guards
  `INV-ADMIN-backup-restore-roundtrip-preserves-logical-state`.
