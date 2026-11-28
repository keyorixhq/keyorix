- **INV-ADMIN-restore-xver-frozen-fixture-decrypts** A FROZEN v2 backup archive —
  committed byte-for-byte under `server/admin/testdata/xver/` next to a sidecar recording
  its canary plaintexts and metadata — must restore into current `main` such that (O1)
  every recorded secret version decrypts, under the restored key files and the exact
  `SecretAAD(secretID, projectID, version)` it was sealed with, to its recorded plaintext,
  the restored secret-version COUNT equals the recorded count (so a silently dropped
  table/version is caught, which `oracleDecrypt`'s tolerate-missing-row behaviour alone
  would not catch), and project/secret/role metadata round-trips; (O2) any mutated archive
  (truncation, bit flip, trailing/oversize bytes, a structurally-valid ciphertext
  corruption, a SHA-consistent manifest tamper, reorder/duplicate/dropped entries, a wrong
  version tag, an oversize declared length) either restores with O1 intact for whatever
  survived, OR is refused with an explicit error that leaves no half-restored rows in the
  target store; (O3) tiny `--max-entry-bytes`/`--max-total-bytes` caps refuse promptly
  rather than buffering the whole payload (resguard); (O4) no canary plaintext and no key
  byte ever appears in restore stdout or error text. The frozen bytes make this a check on
  the READER against a pinned format, not against whatever the current writer happens to
  emit. Why: every other backup round-trip fuzzer writes with the current code
  (`FuzzBackupRestoreRoundTrip`) or reads a real old archive whose plaintexts are unknown
  (`FuzzI6OldArchiveMutation`, `TestI6RestoreOldVersion`), so none would catch a reader
  regression that corrupted or dropped a secret while restoring a frozen pre-upgrade backup;
  task RESTORE-XVER-1. The O1/O2/O4 oracles were red-proofed against three planted reader
  defects (skipped per-entry SHA-256, skipped manifest-signature gate, silent table drop),
  each confirmed to turn the guard red and green again on revert. Guard:
  `server/admin/backup_xver_fixture_fuzz_test.go`
  (`TestXverRestore_O1_DecryptsAndMetadata`, `TestXverRestore_O2_Mutations`,
  `TestXverRestore_O3_BoundedHostileLength`, and `FuzzXverRestore`; SQLite only).
  **Not covered**: PostgreSQL (no DSN wiring here; the PG restore path is covered by
  `FuzzBackupRestoreRoundTrip` when `KEYORIX_TEST_PG_DSN` is set); real N-1/N-2 *binary*
  output (the fixture is current-writer bytes frozen — see its doc comment and
  `INV-BACKUPFMT-oldrelease-restore-lossless` / `scripts/release-qa`); the v1 physical
  format (`readBackupArchive`, covered by `FuzzReadBackupArchive` /
  `TestAdminRestore_V0953Archive`). A *tampered* fixture can only exercise the two
  cryptographic gates (per-entry SHA-256 and manifest signature); the deeper validators
  (referential-integrity/dangling-reference, row-count, schema-delta, atomic staging) are
  only reachable by a TRUSTED-but-buggy archive, so O2's deeper refusals are backstopped in
  depth and this harness does not independently prove each of them in isolation.
<!-- section: Backup and restore -->
