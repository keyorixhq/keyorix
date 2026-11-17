- **INV-ADMIN-backup-refuses-dek-behind-database** On PostgreSQL, `admin backup` archives a key set only
  when its DEK is the one the database's rows are under: the database's `dek.epoch` (read through the
  backup's own REPEATABLE READ snapshot) must be this key directory's DEK fingerprint or `rotating:<it>`,
  or absent together with the `dek_rotation.promote_pending` redo marker. Otherwise it fails non-zero
  before the archive file is created, with no key file changed, and names the fix (finish the rotation in
  the key directory that holds `dek.key.pending`, distribute the new key set, back up again). A failed
  read refuses. Both key paths (the exclusive one and the live-server one) are checked. Why: #4104 (with
  `key_dir_lock: database`, another replica's directory after a committed sweep holds the old `dek.key`
  and no `.pending`: the archive restored, its start was refused and nothing decrypted). Guard:
  `server/admin/backup_rotation_marker_gap_postgres_test.go`
  (`TestAdminBackup_Postgres_RefusedFromAKeyDirectoryBehindACommittedRotation`),
  `server/admin/backup_dek_epoch_guard_postgres_test.go` (`TestRefuseBackupDEKBehindDatabase_Postgres`),
  `server/admin/backup_rotation_marker_gap_test.go`.
