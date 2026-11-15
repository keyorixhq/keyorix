- **INV-STORE-gorm-txn-rmw-no-lost-update** A transactional read-modify-write on a single row
  through `ls.db.WithContext(ctx).Transaction(...)` does not lose updates under concurrency: on
  Postgres the read is taken `FOR UPDATE` (`clause.Locking{Strength: "UPDATE"}`, applied only when
  `tx.Dialector.Name() == "postgres"`), on SQLite the `_txlock=immediate` DSN makes the
  transaction take its write lock at `BEGIN`, and in both cases two concurrent increments of the
  same row observe a strictly serialized sequence of values (never two writers both reading `n`
  and both writing `n+1`). Why: this is the exact shape of `TryAcquireSchedulerLock`
  (`local_scheduler_lock_lease.go`, the dialect-conditional FOR UPDATE on the reclaim read) and of
  `storeNextSecretVersion`'s version-number allocation — a lost update there means two scheduler
  replicas both "win" a tick, or two rotations mint the same version number. Guard:
  `fuzz/thirdparty/pools` `FuzzGormTxnLinearizable` (seeded concurrent transactional counter
  increments on SQLite always, Postgres when `KEYORIX_TEST_PG_DSN` is set, checked for
  linearizability against a monotonic-counter model via porcupine — a lost update surfaces as an
  Illegal history), with the red/green proof in `TestOracle_Isolation_FiresWithoutLock` (the
  non-transactional RMW variant loses an update and the oracle fires) and
  `TestOracle_Isolation_GreenWithLock` (the production locking path stays linearizable). The
  production call sites themselves are additionally guarded by the cross-replica tests under
  `internal/core` (`FuzzCrossReplicaInvariants`) and `server/http`
  (`FuzzConcurrentOpsLinearizable`'s contiguous-version postcondition).
