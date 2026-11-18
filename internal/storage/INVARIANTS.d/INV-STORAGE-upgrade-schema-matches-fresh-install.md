- **INV-STORAGE-upgrade-schema-matches-fresh-install** After an upgrade, every table has the columns
  and explicitly created indexes a fresh install of this tree has (per column: name, type, NOT NULL,
  default and primary key position; per index: name, uniqueness, partial flag and columns), apart from
  the entries in `ugExpectedSchemaDiffs`, each of which names a reason. Why: most steps only ever add
  to an existing table, so a column or index that only the fresh-install tail creates is silently
  absent on upgraded databases. Guard: `internal/storage` `FuzzUpgradeFromOldSchema`,
  `FuzzUpgradeInterrupted`, red-proved by `TestUpgradeOracles_RedProof/invariant6_*`, including a
  listed difference that stops occurring, which is also a failure so an entry cannot outlive what it
  records. A stopped upgrade is held to the same schema: the boot migration runs in one
  transaction (`withMigrationLock`), so a stop leaves nothing half-done for the restart to miss.
  **Not covered**: column order, triggers, the WHERE text of partial indexes, PostgreSQL (the FuzzUpgradePG* targets cover it with their own oracles, see upgrade_pg_fuzz_test.go).
