- **INV-ADMIN-clear-stale-salt-pending-proves-before-removing** `admin encryption clear-stale-salt-pending`
  removes `<salt_path>.pending` and nothing else, and only while it holds the exclusive database lock and the
  exclusive key-directory lock (`dek.lock`, which rotate-kek and a live server hold) and all of these hold:
  no `<dek_path>.pending` exists; the key-set manifest does not need the file
  (`keyfiles.StaleSaltPendingCandidate`: no intent boot would still finish or commit from it); and the DEK
  unwraps under the active KEK with the current passphrase (`Service.Initialize`, the proof boot and
  `AdoptProvenKeySet` rely on). It never removes, moves or writes a DEK's staging file, never calls
  `ReconcileKeySet` or DEK-rotation crash recovery, and refuses in every other case with nothing changed.
  A removal is an `admin.encryption.clear_stale_salt_pending` audit event; a second run has nothing to do;
  `--dry-run` makes every check and removes nothing. Neither boot nor `admin backup` removes the file. Why:
  #4105 (the salt staging file blocked every backup until deleted by hand). Guard:
  `server/admin/encryption_clear_stale_salt_test.go` (`TestClearStaleSaltPending_Refusals`, which checks
  `dek.key.pending` byte-identical in every refused case, `TestClearStaleSaltPending_RemovesItAndTheNextBackupSucceeds`,
  `TestClearStaleSaltPending_OnlyRemovalIsTheSaltStagingFile`), `internal/keyfiles/stale_salt_pending_test.go`
  (`TestStaleSaltPendingCandidate_States`).
<!-- section: Backup and restore -->
