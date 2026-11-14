# SC1 — Concurrency & schedule fuzzing of third-party connection pools / clients

**Report location note:** `/mnt/data/wave4/out/` is outside this session's writable
working directory (the sandbox blocks all access to it), and `.scratch/` is gitignored, so
per the runtime rules this report is committed on the branch at this tracked path,
`docs/fuzzing/sc1-pool-schedule-race.md`.

**Reasonable-reading statement (no questions were asked):**
- "Extend the porcupine approach to these libraries" is read as: fuzz the THIRD-PARTY
  pool/client layer *directly* (not the KeyorixCore layer the existing
  `server/http/concurrent_linearizable_fuzz_test.go` already covers), using the same
  porcupine + sequential-model technique, with a new seeded scheduler helper.
- Redis is **skipped** (stated reason below): no in-process test server (miniredis /
  alicebob) exists in the offline module cache, and Keyorix shares no go-redis client
  across goroutines in production.
- gRPC *client* conns are a **negative result**: Keyorix is a gRPC server; it opens no
  shared client `ClientConn`. Documented, not fuzzed against an unreachable shape.
- PostgreSQL via `KEYORIX_TEST_PG_DSN` (set in this environment); all PG state lives in
  per-run schemas named `sc1_*` and dropped on cleanup. No database is created.

---

## 1. PHASE 0 — which pools/clients Keyorix shares across goroutines, and where cancel/retry live

Source: read-only trace from `server/main.go` boot wiring down through
`internal/storage`. One long-lived `storage.LocalStorage` is built once at boot and shared
by every HTTP and gRPC handler goroutine; it holds several pools:

| Pool / client | Type | Where created | Shared across goroutines? | Fuzzed here |
|---|---|---|---|---|
| Main request pool | `*gorm.DB` over `*sql.DB` | `factory_postgres.go` / `factory_local.go` (`applyPoolSettings`, `factory_pool.go`) | Yes — one instance, all handlers | **Yes** (gorm tx target; sqlite target models the same `database/sql` pool) |
| SQLite request pool | `database/sql` + `modernc.org/sqlite` | `factory.go` `sqliteDSN` (WAL, `_busy_timeout`, `DefaultSQLiteMaxOpenConns`) | Yes | **Yes** (`FuzzSQLitePoolLinearizable`) |
| Native read pool | `*pgxpool.Pool` | `factory_postgres.go:80` → `store/native_reads.go` | Yes (Postgres hot reads) | **Yes** (`FuzzPgxPoolLinearizable`) |
| Scheduler-lock pool | dedicated `*sql.DB` | `factory_postgres.go` `SetSchedulerLockDB` | Yes (advisory-lock sessions) | Indirectly (gorm-tx FOR UPDATE models the lease RMW) |
| Named-lock pool | dedicated `*sql.DB` | `factory_postgres.go` `SetNamedLockDB` | Yes | Not directly |
| go-redis client | `*redis.Client` | `internal/rotation/redis.go` | **No** — built per rotation call, closed immediately | **Skipped** (see §5) |
| gRPC client conn | — | none | **No such object** | **Negative result** (see §5) |

**Transaction / RMW path (the isolation-relevant one):**
`ls.db.WithContext(ctx).Transaction(fn)` (`local_transaction.go`). The row-locking
read-modify-write is `TryAcquireSchedulerLock` (`local_scheduler_lock_lease.go:66`): an
`ON CONFLICT DO NOTHING` insert, then — on conflict — a reclaim read taken `FOR UPDATE`
**only on Postgres** (`clause.Locking{Strength:"UPDATE"}` guarded by
`tx.Dialector.Name()=="postgres"`), then an `Updates`. SQLite relies on `_txlock=immediate`
BEGIN-IMMEDIATE write serialization. `storeNextSecretVersion` has the same shape with a
retry loop. This is exactly what `FuzzGormTxnLinearizable` models.

**Cancellation paths:** context flows HTTP/gRPC handler → core → storage via
`WithContext(ctx)`; `WithTransaction`, `TryAcquireSchedulerLock`, `ReleaseSchedulerLock` all
thread it. Advisory-lock sessions add a liveness watcher
(`advisory_lock_session.go watch`) that cancels the critical section with
`ErrAdvisoryLockLost` on connection death. SQLite busy-retry loops respect `ctx.Done()`.

**Retry paths:** SQLite busy-timeout retry (`local_audit_chain.go`
`commitBatchWithBusyRetry`), `storeNextSecretVersion`'s conflict-retry loop,
`TryAcquireSchedulerLock`'s `ON CONFLICT DO NOTHING` (conflict-avoidance, not catch — the
Postgres "a caught constraint violation aborts the transaction" rule from CLAUDE.md).

---

## 2. Design — seeded scheduler + targets

**Seeded scheduler** `internal/testutil/schedfuzz` (new, test-only): decodes a fuzz `[]byte`
into bounded goroutines each carrying an op list with a per-op `Yield`
(`runtime.Gosched`) and bounded micro-`Sleep` bit, plus a `GOMAXPROCS` choice — the corpus
controls *where* yields land so a reduced crasher replays. `RunBounded` is the deadlock
watchdog (all goroutines must finish within a timeout); `GoroutineBaseline` /
`SettleGoroutines` back the goroutine-leak oracle.

**Models** (`kvmodel_test.go`): `regModel` (string register: write UPSERT / read) for the
plain-pool targets, where each op is a single atomic statement so the history must be
linearizable — a violation would be a genuine pool defect (a reply delivered to the wrong
connection). `counterModel` (monotonic counter, transactional RMW) for the gorm target,
where linearizability == no lost update == the transaction-isolation oracle.

**Targets:** `FuzzSQLitePoolLinearizable`, `FuzzPgxPoolLinearizable`,
`FuzzGormTxnLinearizable` (see table in §4 and the conf files).

---

## 3. Oracles and — for EVERY oracle — what it does NOT verify

| Oracle | Mechanism | Does NOT verify |
|---|---|---|
| Linearizability (register) | porcupine `CheckOperationsVerbose(regModel, …)` | durability; multi-statement isolation; performance/fairness; **cancelled ops are leak-probes only, NOT recorded** — says nothing about a cancelled op's success/failure |
| Linearizability / isolation (counter) | porcupine `counterModel`; lost update ⇒ Illegal | aborted/retried-txn liveness; isolation anomalies other than lost-update (no write-skew/phantom model — single-row RMW by construction) |
| Pool returns to baseline | `db.Stats().InUse==0` / `pool.Stat().AcquiredConns()==0` | that OpenConnections/idle count shrinks (idle pooled conns legitimately remain); pool sizing / wait time |
| No conn leak after mid-query cancellation | same drain check after cancelling a fraction of queries mid-flight | the cancelled query's result; whether cancellation was timely |
| No goroutine leak | `SettleGoroutines(baseline, slack)` | WHICH goroutine leaked; tolerates bounded slack for pool-internal goroutines |
| No deadlock within timeout | `RunBounded` watchdog | liveness beyond the timeout; a merely-slow run near the bound can read as a false positive (timeout set generously) |

**Red/green proof status:** all six oracles proven in `oracles_test.go` — each plants a
defect (non-linearizable history; a real lost update via a non-transactional RMW; a
leaked `*sql.Conn`; a permanently-blocked goroutine) and asserts the oracle FIRES, plus
asserts the good path is GREEN. The plants live only in the tests; no production path is
modified. **Status: PASS under `-race`** (see §6).

---

## 4. Findings table

| # | Target / area | Classification | Status |
|---|---|---|---|
| — | all three pool targets, seed corpus + oracle self-tests, `-race`, SQLite + Postgres | green | PASS |
| — | fuzzing in progress; hits triaged below as they arrive | — | pending |

*(Updated continuously during the fuzz run — see §6.)*

---

## 5. Negative results / skips (with reasons)

- **Redis (go-redis) — SKIPPED.** (1) No in-process test server in the offline module
  cache: `grep miniredis|alicebob go.sum` is empty, and `GOPROXY=off` forbids fetching one,
  so a client-side concurrency harness could not run without a network Redis. (2) No live
  Keyorix caller shares a go-redis client across goroutines: `internal/rotation/redis.go`
  constructs one `redis.NewClient` per rotation call and closes it immediately
  (`defer c.Close()`), so there is no shared-pool shape to fuzz. A harness here would fuzz
  an unreachable deployment shape.
- **gRPC client conns — NEGATIVE RESULT.** Keyorix is a gRPC *server*; a repo-wide search
  found no `grpc.Dial` / `grpc.NewClient` / shared `*grpc.ClientConn` in production code.
  There is no client connection pool to fuzz. Recorded, not fuzzed.

---

## 6. Fuzz run log & triage

*(Filled in as chunks complete. Each chunk is one foreground
`go test -fuzz … -fuzztime 540s -race -parallel 2`, GOMAXPROCS=2, nice -n 10.)*

Pending — see end of report for the running tally.

---

## 7. Talk material

*(Filled in at the end.)*

---

## Deliverables (paths)

- Seeded scheduler: `internal/testutil/schedfuzz/schedfuzz.go`
- Models + history: `fuzz/thirdparty/pools/kvmodel_test.go`
- Targets: `fuzz/thirdparty/pools/{sqlitepool,pgxpool,gormtx}_fuzz_test.go`
- Oracle red/green proofs: `fuzz/thirdparty/pools/oracles_test.go`
- targets.d confs: `scripts/fuzzing/targets.d/fuzz-thirdparty-pools__Fuzz{SQLitePool,PgxPool,GormTxn}Linearizable.conf` (+ regenerated `targets.conf`)
- Changelog: `changelog.d/fuzz-pool-schedule-race.md`
- Invariant: `internal/storage/store/INVARIANTS.d/INV-STORE-gorm-txn-rmw-no-lost-update.md`
- This report (committed copy): `docs/fuzzing/sc1-pool-schedule-race.md`
