- **INV-ADMIN-backup-refusal-in-posture** While `admin backup` would refuse because a key-rotation staging
  file is present, `admin validate --posture` reports the deviation `[backup] backups are refused: key-rotation
  staging file present (<file>)` and exits non-zero; it calls the backup's own check
  (`refusePendingKeyRotation`), so the two cannot disagree. Each refused backup also writes an
  `admin.backup_refused` audit event (`success=false`, naming the files) when storage can be opened without
  changing anything: under the lock the backup itself would hold, and only when the database already records
  this binary's schema epoch (`storage.SchemaEpochIsCurrent`), so a refused backup never migrates the
  database. When it cannot, the event is skipped with a stderr note and the backup is refused exactly the same
  (exit 4). A leftover `kek.salt.pending` gets the remedy `admin encryption clear-stale-salt-pending`; a DEK's
  `.pending` is never suggested for removal. Why: #4105 (under cron with stderr discarded, backups stopped
  silently). Guard: `server/admin/backup_stale_salt_pending_test.go`
  (`TestAdminBackup_StaleSaltPendingAfterBoot_RefusedVisiblyUntilRemoved`,
  `TestPosture_ReportsPendingDEKBackupRefusal`), `server/admin/encryption_clear_stale_salt_test.go`
  (`TestAdminBackup_StaleSaltPending_RefusalIsAuditedAndInPosture`,
  `TestAdminBackup_StaleSaltPending_RefusedEvenWhenTheAuditWriteIsSkipped`).
