- **INV-SERVERGUARD-lost-lock-leaves-no-backup** An `admin backup` whose lock is found lost
  before its archive is closed leaves no archive and exits non-zero with an error saying the
  backup is not usable, whichever lock it holds: the exclusive one (SQLite, `--exclusive`;
  `Exclusive.Lost`) or the live PostgreSQL backup's shared presence lock under
  `key_dir_lock: database` (`Presence.Lost`). Writes to the archive stop at the next one, the
  snapshot reads are cancelled, and the lock is looked at once more after the file is closed,
  under `lostLockMu`, so a loss up to the close fails the backup. The exclusive path's stop is an
  `os.Exit` from `stopOnLostDatabaseLock`, which skips defers, so the archive's removal is
  registered with `onLostDatabaseLock` right after the O_EXCL create and runs before the exit.
  Why: the archive is written in place, and a key rotation, a restore or a server may have run
  beside a backup whose lock was lost (POOLER-LOCKLOSS-1 "Not changed", ADMIN-TAILS-1,
  SERVERGUARD-LOCK-TAILS-1). Guard: `server/admin`
  `TestAdminBackup_SQLiteLockLost_NoArchiveAndNonZeroExit` and
  `TestAdminBackup_Postgres_LivePresenceLost_NoArchiveAndNonZeroExit` (before the first byte,
  mid-stream, after the last byte before close; through `Execute`),
  `TestAdminBackup_SQLiteLockLostMidStream_RemovesTheArchive` (the archive is gone when the
  command is stopped), `TestAdminBackup_Postgres_RealPresenceLockLost_NoArchive` (real lock,
  `pg_terminate_backend`), `TestAdminBackup_SQLiteLockHeld_ArchiveWritten` (control). **Not
  covered**: a loss that happens before the close but is noticed after it (detection takes up to
  one watch interval, plus the ping timeout on PostgreSQL); other admin commands that write an
  output file in place register no cleanup.
<!-- section: Lock loss -->
