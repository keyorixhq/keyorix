- **INV-ADMIN-restore-keys-after-commit** `admin restore` (v2) changes a target's key files
  only after its data has committed: the archive's key files and the SQLite database are
  staged beside their targets and recorded in the restore journal, PostgreSQL rows load in one
  transaction, and only then are the staged files renamed into place. A failure or a kill
  before that point leaves the target's key files (and their key-set manifest) byte-identical;
  while a journal exists every plain restore is refused until `admin restore --recover` rolls
  it back (data not committed) or forward (committed). A PostgreSQL target holding Keyorix
  rows is refused at the checks stage unless `--overwrite-existing` is given, which empties it
  inside the load transaction. Why: RESTORE-POPULATED-PG-1 (#3618) and #3583 — keys installed
  first, then a failed load, left the old database next to the new keys. Guard:
  `server/admin/restore_overwrite_atomicity_test.go` (`TestAdminRestore_Overwrite_KillPoints`,
  `TestAdminRestore_Overwrite_FailingLoad_LeavesPreRestoreStateIntact`),
  `server/admin/restore_populated_target_test.go` (the Postgres ones are pg-gated),
  `server/admin/restore_keyset_journal_interaction_test.go`
  (`TestAdminRestore_KilledMidInstall_RefusalsAndRecovery`), and the kill -9 legs of
  `scripts/migrate/sqlite-to-pg-check.sh` (manual drill). Not guarded: the v1 (physical
  archive) ordering.
<!-- section: Backup and restore -->
