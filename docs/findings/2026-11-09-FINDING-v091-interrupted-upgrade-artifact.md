# v0.91.0 interrupted-upgrade "column never added": harness artefact on the real path

Classification: ARTIFACT (of the SQLite leg's interruption harness), with a residual
HARDENING note below.

## What was reported

The SQLite leg of the upgrade fuzzer (branch `fuzz/migration-upgrade`, report w3)
recorded a DEFECT: an upgrade from v0.91.0 stopped at write statement 34 or later
leaves `secret_nodes` without `owner_machine_identity_id`, and every secret read then
fails permanently. Pinned by `TestUpgradeInterrupted_V091_ColumnNeverAdded`.

## What this leg found

That test's interruption calls `migrateDatabase` directly on an autocommit
connection (`ugInterruptedMigrate`). No production boot does. `createLocalStorage`
runs the migration through `withMigrationLock`, which holds one `BEGIN EXCLUSIVE`
transaction across the whole of it (`withSQLiteInDBMigrationLock`,
INV-STORAGE-23). A stop on that path rolls back everything, including the
`mfa_step_up_grants` table whose presence is what made the bare-path restart skip
the fresh-install tail.

PostgreSQL has the same structure by code reading (`withMigrationLockPooled` wraps
`migratePostgres` in one `db.Transaction`), but this was NOT run on PostgreSQL: the
lab tunnel went down before any PostgreSQL snapshot existed. The comparison test
`TestUpgradePGInterrupted_V091_Compare` is committed and has never executed.

`TestUpgradeInterrupted_V091_SQLite_RealPath`
(`internal/storage/upgrade_pg_redproof_test.go`) takes the real path with the same
fail-stop callbacks at statements 34, 41 and 200. It asserts the stop was reached
(the migration returned the injected error and at least that many statements were
seen), restarts through `CreateStorage`, and reads a secret. It passes, while
`TestUpgradeInterrupted_V091_ColumnNeverAdded` still passes on the bare path.

Replayed 3 times on the same tree, same result.

## Residual note (HARDENING, not a defect)

The bare-path result is still a true statement about `migrateDatabase` itself: the
fresh-install tail is the only thing that adds `owner_machine_identity_id` to a
v0.91.0 schema, and that tail is gated on `mfa_step_up_grants` being absent. Atomicity
is what keeps that gate honest. If `migrateDatabase` is ever called outside the lock,
or a step is moved out of the transaction, the defect becomes real. v0.91.0 is also
below the documented v0.93.x upgrade floor.

## Effect on the existing test

`TestUpgradeInterrupted_V091_ColumnNeverAdded` and `ugInterruptibleFrom = 1` describe
a production defect that the real path does not have. `ugRun` should interrupt
through `withMigrationLock` so v0.91.0 can rejoin `FuzzUpgradeInterrupted`. Left
unchanged here (new files only); a decision for the maintainer.
