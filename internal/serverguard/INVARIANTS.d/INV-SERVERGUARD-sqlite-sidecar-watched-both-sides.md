- **INV-SERVERGUARD-sqlite-sidecar-watched-both-sides** Both holders of the SQLite
  `<database>.server.lock` flock (a server's LOCK_SH presence, an admin command's LOCK_EX
  exclusive hold) check every `config.PinnedLockPingInterval` (5 s) that the path still names
  the inode they locked (`sidecarWatch`), and at acquisition, after the flock, that it named it
  then (`lockSidecar`). When the sidecar was deleted or replaced, a server takes LOCK_SH on the
  file the path now names and keeps running, or closes `Presence.Lost` when it cannot; an admin
  command takes LOCK_EX on the new file (so no second acquisition gets in until it stops) and
  closes `Exclusive.Lost` either way, and `server/admin` `stopOnLostDatabaseLock` stops it with
  exit 1. Why: REVIEW-SERVERGUARD-RECOVERYKEY-1 F4
  (an admin command took the exclusive lock beside a live server after the sidecar was deleted),
  SERVERGUARD-WATCHER-1 (server side), SERVERGUARD-LOCK-TAILS-1 (admin side: a server started
  beside a running admin command). Guard: `internal/serverguard`
  `TestSQLitePresence_DeletedSidecarIsTakenAgain`,
  `TestSQLitePresence_DeletedSidecarTakenByAdminFirst_ClosesLost`,
  `TestSQLiteExclusive_DeletedSidecarClosesLost`, `TestSQLiteExclusive_ReplacedSidecarClosesLost`,
  `TestSQLiteExclusive_ServerGotInFirst_ClosesLost`, `TestSQLiteExclusive_HealthySidecarNeverReportsLost`
  (control), the acquire-race family in `serverguard_sidecar_acquire_race_test.go`; `server/admin`
  `TestAcquireDatabaseLock_SQLiteSidecarDeleted_StopsTheCommand`. **Not covered**: a process that
  starts and finishes inside one interval after the deletion ran beside the holder unseen.
<!-- section: SQLite sidecar -->
