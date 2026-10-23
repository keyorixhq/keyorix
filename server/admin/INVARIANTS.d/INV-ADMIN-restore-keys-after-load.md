- **INV-ADMIN-restore-keys-after-load** `admin restore` changes a target's key files only after
  its database is in place: v2 renames the archive's key files into place only after the row
  load transaction has committed (they are staged, written and fsynced beside their targets,
  inside that transaction); v1 only after the database file is installed. A failure before
  that point leaves the target's key files byte-identical and puts a SQLite database moved
  aside by `--overwrite-existing` back. A PostgreSQL target that holds any Keyorix row is
  refused before anything is changed, with or without `--overwrite-existing`, because restore
  never deletes rows. Why: RESTORE-POPULATED-PG-1 — keys installed first, then a load that
  collided on a populated PostgreSQL database, left the old database next to the new keys.
  Guard: `server/admin/restore_populated_target_test.go`
  (`TestAdminRestore_Postgres_OverwriteExisting_PopulatedTarget_StaysConsistent`,
  `_PopulatedTarget_RefusedUpFront`, `_LoadFailure_LeavesKeyFiles`, `_EmptySchema_Succeeds`,
  `TestAdminRestore_SQLite_OverwriteExisting_LoadFailure_RestoresOldDatabase`; the Postgres
  ones are pg-gated). Not guarded: the v1 ordering, and a crash between the COMMIT and the
  key-file renames (the target then holds the new rows with the old keys, recovered by
  re-running the restore into an empty database).
<!-- section: Backup and restore -->
