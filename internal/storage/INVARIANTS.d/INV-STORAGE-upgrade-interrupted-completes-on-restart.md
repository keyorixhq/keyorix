- **INV-STORAGE-upgrade-interrupted-completes-on-restart** An upgrade stopped after any write
  statement finishes on the next boot, with the other upgrade invariants intact
  (INV-STORAGE-upgrade-secrets-still-decrypt, -authz-unchanged, -audit-intact, -rerun-is-no-op,
  -schema-matches-fresh-install). Why:
  operators restart after a crash and expect the database to converge, not to need a restore. Guard:
  `internal/storage` `FuzzUpgradeInterrupted`, red-proved by
  `TestUpgradeOracles_RedProof/invariant5_*`. Every source is covered, v0.91.0 included: the interruption goes through the real boot path, and the
  bare-path artefact is pinned by `TestUpgradeInterrupted_V091_BarePathArtefact`. A stop that
  never fires is skipped with its reason, never passed
  (`TestUpgradeInterrupted_StopThatNeverFiresIsNotAPass`). **Not
  covered**: the stop is fail-stop at the gorm statement layer (no torn write inside SQLite);
  PostgreSQL (the FuzzUpgradePG* targets cover it with their own oracles, see upgrade_pg_fuzz_test.go).
