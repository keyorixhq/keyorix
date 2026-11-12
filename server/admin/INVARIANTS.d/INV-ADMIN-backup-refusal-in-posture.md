- **INV-ADMIN-backup-refusal-in-posture** While `admin backup` would refuse because a key-rotation staging
  file is present, `admin validate --posture` reports the deviation `[backup] backups are refused: key-rotation
  staging file present (<file>)` and exits non-zero; it calls the backup's own check
  (`refusePendingKeyRotation`), so the two cannot disagree. A leftover `kek.salt.pending` gets advice to
  move it out of the key directory once a server start has proved the active set opens without it; a DEK's
  `.pending` is never suggested for removal. Why: #4105 (the refusal runs before storage or the audit log
  is opened, so under cron with stderr discarded backups stopped silently). Guard:
  `server/admin/backup_stale_salt_pending_test.go`
  (`TestAdminBackup_StaleSaltPendingAfterBoot_RefusedVisiblyUntilRemoved`,
  `TestPosture_ReportsPendingDEKBackupRefusal`).
