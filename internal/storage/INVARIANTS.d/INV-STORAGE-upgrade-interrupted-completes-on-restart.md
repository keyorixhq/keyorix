- **INV-STORAGE-upgrade-interrupted-completes-on-restart** An upgrade stopped after any write
  statement finishes on the next boot, with the other upgrade invariants intact
  (INV-STORAGE-upgrade-secrets-still-decrypt, -authz-unchanged, -audit-intact, -rerun-is-no-op,
  -schema-matches-fresh-install). Why:
  operators restart after a crash and expect the database to converge, not to need a restore. Guard:
  `internal/storage` `FuzzUpgradeInterrupted`, red-proved by
  `TestUpgradeOracles_RedProof/invariant5_*`. **Open defect**: v0.91.0 is outside the target
  (`ugInterruptibleFrom`) because a stopped upgrade from it never gains
  `secret_nodes.owner_machine_identity_id`, so every secret read fails afterwards;
  `TestUpgradeInterrupted_V091_ColumnNeverAdded` pins it and goes red when it is fixed. A stop that
  never fires is skipped with its reason, never passed
  (`TestUpgradeInterrupted_StopThatNeverFiresIsNotAPass`). **Not
  covered**: the stop is fail-stop at the gorm statement layer (no torn write inside SQLite);
  PostgreSQL in this target.
