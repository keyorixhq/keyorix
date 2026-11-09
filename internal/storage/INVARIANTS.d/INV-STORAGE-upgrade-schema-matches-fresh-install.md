- **INV-STORAGE-upgrade-schema-matches-fresh-install** After an upgrade, every table has the columns
  and explicitly created indexes a fresh install of this tree has (per column: name, type, NOT NULL,
  default and primary key position; per index: name, uniqueness, partial flag and columns), apart from
  the entries in `ugExpectedSchemaDiffs`, each of which names a reason. Why: most steps only ever add
  to an existing table, so a column or index that only the fresh-install tail creates is silently
  absent on upgraded databases. Guard: `internal/storage` `FuzzUpgradeFromOldSchema`,
  `FuzzUpgradeInterrupted`, red-proved by `TestUpgradeOracles_RedProof/invariant6_*`, including a
  listed difference that stops occurring, which is also a failure so an entry cannot outlive what it
  records. **Open**: `ugStopWindowDiffs` are unique and plain indexes a crash between creating a table
  or column and its index loses for good; `TestUpgradeInterrupted_KnownIndexGaps_StillOpen` pins them.
  **Not covered**: column order, triggers, the WHERE text of partial indexes, PostgreSQL in this target.
