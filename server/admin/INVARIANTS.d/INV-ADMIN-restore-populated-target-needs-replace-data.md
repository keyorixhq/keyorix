- **INV-ADMIN-restore-populated-target-needs-replace-data** `admin restore --overwrite-existing`
  (v1 and v2, SQLite and PostgreSQL) refuses a target database that holds data unless
  `--replace-existing-data` is also given: any row in a model-registry table other than
  `system_metadata`, except `audit_events` rows with actor `admin_cli` (what `admin init`,
  `migrate` or a rolled-back `restore --recover` write on a fresh host). The refusal
  (`ErrRestoreTargetPopulated`) comes with the other checks, before the archive is extracted
  and before any key file or manifest is staged, so the key files, the key-set manifest and
  the database are byte-identical afterwards. `--replace-existing-data` without
  `--overwrite-existing` is refused. Why: MIGRATE-VERIFY-1 (b) — the re-run flag also
  replaced a working deployment, and on PostgreSQL deleted its rows. Guard:
  `server/admin/restore_populated_refusal_test.go`
  (`TestAdminRestore_{SQLite,Postgres}_OverwriteExisting_PopulatedTarget_RefusedKeysByteIdentical`,
  the Postgres one pg-gated), `server/admin/restore_replace_existing_data_test.go`. Not
  guarded: a table outside the model registry (it is neither checked nor emptied).
<!-- section: Backup and restore -->
