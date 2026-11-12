- **INV-ADMIN-backup-refuses-pending-rotation** `admin backup` never archives a key rotation's `.pending`
  staging file (`<dek_path>.pending`, `<salt_path>.pending`): while either exists it fails non-zero with no
  archive written and the staging file left in place, naming the file and the fix ("start the server once so
  boot recovery completes the rotation, then back up again"). `admin restore` compares the archive's key files
  with its target's, so such an archive restores only on a host with the same leftover and is refused on a
  clean one, when the backup is needed. The check runs before the passphrase and again under the key lock. Why:
  #4058. Guard: `server/admin/backup_pending_rotation_test.go`
  (`TestAdminBackup_RefusedWhileARotationIsPending`, `TestReadKeyFilesForBackup_RefusesAPendingRotation`,
  `TestAdminBackup_RefusalThenRecovery_RestoresOnSameAndCleanHost`),
  `internal/keyfiles/pending_rotation_test.go` (`TestPendingRotationFiles_AgreesWithRegistry`),
  `internal/encryption/keyset_pending_backup_test.go` (`TestRotateKEKCrashPoints_PendingFilesBackupRefusesOn`).
<!-- section: Backup and restore -->
