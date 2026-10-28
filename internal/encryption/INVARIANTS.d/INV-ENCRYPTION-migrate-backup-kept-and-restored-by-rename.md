- **INV-ENCRYPTION-migrate-backup-kept-and-restored-by-rename** `migrate-provider`'s backup
  of the wrapped DEK is never overwritten or deleted while the migration that made it may
  still need it, and the rollback never leaves a torn DEK: each backup is a new O_EXCL file
  `<dek_path>.migrate-backup.<unix-ns>-<random>` (`CreateMigrateBackup`), the rollback writes
  `<backup>.restoring` and renames it over `dek_path` (`RestoreBackup`), and
  `migrate-provider cleanup` holds `dek.lock` exclusively, which migrate-provider holds for
  its whole run, so `--force` cannot put a cleanup beside it. Why: REVIEW-ENCRYPTIONOPS-1
  R1/R2; the in-place restore tore `dek.key` on a failed write, a second run in the same
  second truncated the first backup, and a forced cleanup could delete the backup the
  rollback needed. Guard: `internal/encryptionops/migrate_backup_atomic_test.go`
  (`TestRestoreBackup_CrashBeforeRenameLeavesTheActiveDEKIntact`,
  `TestCreateMigrateBackup_SameInstantGetsDistinctNamesAndNeverOverwrites`,
  `TestCreateMigrateBackup_NameCollisionNeverTruncates`),
  `migrate_backup_atomic_darwin_test.go` (a failed write, RLIMIT_FSIZE),
  `migrate_cleanup_lock_test.go`. **Not covered**: a kill between the re-wrap and the
  verification still leaves `dek.key` under the target provider for a human to resolve;
  boot names the newest backup in its unwrap error (`unwrap_hints.go`) and the runbook gives
  the recovery.
