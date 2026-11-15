### Testing
- **Concurrency/linearizability fuzzers for the third-party connection pools Keyorix shares
  across goroutines.** New `fuzz/thirdparty/pools` package with a seeded scheduler
  (`internal/testutil/schedfuzz`) driving concurrent operation histories against three pools,
  each checked for linearizability with porcupine and watched by connection-leak (including
  mid-query/mid-transaction context cancellation), pool-drain-to-baseline, goroutine-leak, and
  deadlock-within-timeout oracles, run under `-race`: `FuzzSQLitePoolLinearizable`
  (`database/sql` + `modernc.org/sqlite`), `FuzzPgxPoolLinearizable` (`jackc/pgx/v5/pgxpool`,
  the native read pool, `KEYORIX_TEST_PG_DSN`-gated), and `FuzzGormTxnLinearizable` (gorm
  transactional read-modify-write, the `TryAcquireSchedulerLock` FOR-UPDATE shape, with a
  monotonic-counter model whose linearizability is the transaction-isolation / lost-update
  oracle). Every oracle has a committed red/green proof (`TestOracle_*`). New store invariant
  `INV-STORE-gorm-txn-rmw-no-lost-update`.
