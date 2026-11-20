- **INV-STORAGE-upgrade-rerun-is-no-op** Booting a second time on an upgraded database changes
  nothing: the schema and every row of every table read back identical. Why: `migrateDatabase` runs
  its whole step list on every boot, so a step that is not idempotent keeps changing data on each
  restart. Guard: `internal/storage` `FuzzUpgradeFromOldSchema`, `FuzzUpgradeInterrupted`, red-proved
  by `TestUpgradeOracles_RedProof/invariant4_*`. **Not covered**: WAL state (a rerun that only
  checkpoints reads as no change), PostgreSQL (the FuzzUpgradePG* targets cover it with their own oracles, see upgrade_pg_fuzz_test.go).
