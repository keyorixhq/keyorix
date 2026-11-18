- **INV-HTTP-backup-refused-signal** While a key-rotation staging file is in the answering
  replica's key directory, `GET /api/v1/system/info` carries `security.backup_refused` for a
  caller with `system.write` (reason `key-rotation-staging-file`, the files, `staging_salt_only`,
  a remedy), and omits it once the file is gone. It calls `keyfiles.PendingRotationFiles`, the
  check `admin backup` refuses on, and the reason is `keyfiles.BackupRefusedReasonStagingFile`,
  the `reason=` of the backup's `keyorix-backup-refused` line, so the two cannot disagree. A
  check that fails reports `staging-file-check-failed` (fail closed), without the error text.
  Reading it only stats the files: it never opens, moves or deletes one, and a DEK's `.pending`
  is never suggested for removal. A caller without `system.write` never sees the field (it names
  key-file paths). Why: #4105 (the backup refuses before it opens storage, so it writes no audit
  event, and under cron with stderr discarded backups stopped silently).
  Guard: `server/http/backup_refused_signal_test.go`
  (`TestSystemInfo_BackupRefused_StaleSaltPending_SignalsUntilRemoved`,
  `TestSystemInfo_BackupRefused_DEKPending_ReportedAndNeverTouched`,
  `TestSystemInfo_BackupRefused_CheckFailure_FailsClosed`);
  `server/admin/backup_dek_pending_untouched_test.go`
  (`TestBackupRefusedLine_ReasonIsTheServerSignalsReason`); journey
  `TestJourney_BackupRefusedSignalWhileStagingSaltPresent`.
  **Not covered**: the database side of the backup gate (`refuseBackupDEKBehindDatabase`, needs
  the KEK) and the restore journal (`restorejournal.RefuseIfPresent`) are not reported here.
