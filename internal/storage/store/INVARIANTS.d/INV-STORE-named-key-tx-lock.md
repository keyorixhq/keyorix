- **INV-STORE-named-key-tx-lock** `LockNamedKeyInTx` (local_named_lock_tx.go) is the
  transaction-scoped fence for a `WithNamedLock` key: on PostgreSQL it is
  `pg_advisory_xact_lock` on the key's FNV-1a hash split into the TWO-int4 key space, taken
  inside the caller's write transaction and released by PostgreSQL when that transaction
  ends, so it cannot outlive the write it fences. Two rules hold it together:
  (1) its key space must stay disjoint from `WithNamedLock`'s one-bigint session key: the
  session lock is on a lock-pool connection and the holder's transaction on a request-pool
  connection (another backend), so a shared key makes every holder wait on itself forever;
  (2) it refuses (error, nothing taken) on a `LocalStorage` that is not transaction-bound,
  because an autocommit statement would release the lock at once and fence nothing.
  On SQLite it takes nothing (BEGIN IMMEDIATE, one process: write transactions are already
  serialized) but rule (2) still applies.
  Why: NAMEDLOCK-OVERLAP-2. Option E of docs/design/pooler-lock-loss.md applied to the write
  half of each named-lock section (docs/design/named-lock-overlap.md).
  Guard: pg-gated, `local_named_lock_tx_postgres_test.go`
  (`TestLockNamedKeyInTx_Postgres_SameKeyWaitsForFirstTransaction`,
  `_DifferentKeyDoesNotWait`, `_InsideOwnNamedLockDoesNotSelfDeadlock`,
  `_WaiterHonoursContext`, `_OutsideTransactionIsRefused`, and the premise test
  `TestNamedLockXactKey_Postgres_SharedBigintKeyWouldSelfDeadlock`); default-ci,
  `local_named_lock_tx_test.go` (`TestLockNamedKeyInTx_SQLite_*`,
  `TestNamedLockXactKey_IsTheSessionKeyHashSplit`).
<!-- section: Named locks (`WithNamedLock`) -->
