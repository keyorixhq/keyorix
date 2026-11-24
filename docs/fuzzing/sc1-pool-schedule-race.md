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

| # | Target / area | Observation | Classification | Trace to live Keyorix caller |
|---|---|---|---|---|
| F1 | `FuzzSQLitePoolLinearizable`, first contact | `read()->"v23"` flagged NOT LINEARIZABLE with a lone op | **ARTIFACT** (harness bug, fixed in fixture) | n/a — see triage T1 |
| — | all three targets, ~128 min `-race`, SQLite + Postgres, post-fix | no linearizability violation, no leak, no deadlock, no panic/race | green | — (no defect to trace) |
| N1 | go-redis | no shared pool; no in-cache test server | **NEGATIVE RESULT / SKIP** | n/a (§5) |
| N2 | gRPC client conns | Keyorix opens none | **NEGATIVE RESULT** | n/a (§5) |
| H1 | PG schema hygiene on the shared test server | killed fuzz workers leak `sc1_*` schemas | **HARDENING (test infra, not product)** | n/a — see triage T2 |

No VULNERABILITY / SECURITY-DEFECT / DEFECT / CANDIDATE findings. The one hit (F1)
was a harness false positive caught by the oracle on first contact and fixed in the
fixture, exactly as the CLAUDE.md rule prescribes ("fix the harness, do not weaken the
oracle"). No upstream-library defect was observed, so no upstream reproducer is owed.

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

Each chunk is one foreground `go test -fuzz … -fuzztime 540s -race -parallel 2`,
`GOMAXPROCS=2`, `nice -n 10`, against SQLite always and Postgres (`KEYORIX_TEST_PG_DSN`)
where the target uses it. All chunks exited 0 (green).

| Chunk | Target | fuzztime | execs | new-interesting (total corpus) | result |
|---|---|---|---|---|---|
| verify | sqlite | 90s | 85 | 3 (7) | green (post-fix) |
| sqlite #2 | sqlite | 540s | 780 | 19 (26) | green |
| sqlite #3 | sqlite | 540s | 301 | 18 (44) | green |
| sqlite #4 | sqlite | 540s | 1207 | 18 (62) | green |
| sqlite #5 | sqlite | 540s | 1691 | 16 (78) | green |
| pgx #1 | pgx | 540s | 32875 | 45 (48) | green |
| pgx #2 | pgx | 540s | 10962 | 20 (68) | green |
| pgx #3 | pgx | 540s | 10831 | 18 (86) | green |
| pgx #4 | pgx | 540s | 19843 | 23 (109) | green |
| pgx #5 | pgx | 540s | 13951 | 20 (129) | green |
| gorm #1 | gorm | 540s | 539 | 19 (22) | green |
| gorm #2 | gorm | 540s | 1139 | 19 (41) | green |
| gorm #3 | gorm | 540s | 565 | 16 (57) | green |
| gorm #4 | gorm | 540s | 484 | 16 (73) | green |
| gorm #5 | gorm | 540s | 335 | 16 (89) | green |

**Total real fuzz wall time ≈ 128 min** (sqlite ≈ 37 min incl. verify, pgx ≈ 45 min,
gorm ≈ 45 min), each target ≥ 8 min, total ≥ 120 min. Throughput is intentionally low for
the SQLite/gorm targets: every iteration is a heavyweight real-DB concurrent interleaving
(WAL fsync, per-iteration table reset, transactional RMW) run under `-race` — the value is
in the breadth of interleavings exercised, not raw exec count. The pgx target is faster
(no local fsync) and drove the corpus to 129 interesting inputs. Temperature stayed in the
66–90 °C band (peaked 90 °C mid-run, never the 92 °C pause threshold); all runs kept
`nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`.

### Triage

**T1 — F1, first-contact harness false positive (ARTIFACT).** On the very first SQLite
chunk the linearizability oracle fired in ~3 s: a single `read()->"v23"` with no matching
write in the recorded history. Minimised and root-caused in one pass: the pool and its `kv`
table are built once and reused across fuzz iterations, so a read could observe a value a
*prior* iteration wrote — not in the current history — which `regModel`'s `Init:""`
correctly rejects. A second latent variant: a cancelled leak-probe *write* can still commit
and mutate a recorded key unobserved. **Fix was in the fixture, never the assertion**
(CLAUDE.md "fix the harness, do not weaken the oracle"): clear recorded keys before each
concurrent phase, and move leak-probe writes to a disjoint `probe*` keyspace the model
never reads. Re-ran 90 s + 128 min green. This is itself the strongest evidence the
linearizability oracle is load-bearing: it caught a real history inconsistency on first
contact, and the red/green proofs (`TestOracle_Linearizability_*`) show it distinguishes
legal from illegal histories deterministically.

**T2 — H1, leaked `sc1_*` schemas on the shared PG server (HARDENING, test infra).**
After the run, 29 `sc1_pool_*` / `sc1_gormtx_*` schemas remained. Root cause: `go test
-fuzz` kills its worker subprocesses at the deadline without running `tb.Cleanup`, so the
per-process schema drop never fires for a worker. Not a product defect and not a leak in
any library — a shared-test-server hygiene gap in these harnesses. Mitigated here by a
sweep that drops every `sc1_%` schema (left Postgres at 0 leftover). **Issue-ready
proposal:** add a `TestMain`/package-level pre-run sweep that drops stale `sc1_%` schemas
older than N minutes, or name schemas under a single per-invocation parent schema dropped
by the coordinator process (which is not killed); the rig's session-start cleanup should
also `DROP SCHEMA ... sc1_%`. No production change.

**Replay note:** no crashing input was produced that survived triage (F1 was fixed, not a
crasher), so there is no minimised crasher to replay 3×. The oracle red/green proofs stand
in for replay determinism: each is deterministic and was observed to fire and to pass.

---

## 7. Talk material

The most striking result is a negative one, and it is the point. Across ~128 minutes of
real-time, `-race`-instrumented, seeded-scheduler fuzzing of pgx's pool, `database/sql` +
modernc SQLite, and gorm transactions — the three third-party pools a running Keyorix
shares across every handler goroutine — the linearizability checker and the leak/deadlock
oracles found **zero** real defects: these libraries hold their guarantees under the
interleavings Keyorix actually subjects them to. The single hit came in the first three
seconds and was *our* bug, not theirs: a read saw a value from a previous iteration because
the test reused one pool across iterations without resetting the table. That is exactly the
failure mode the repo's own doctrine warns about — a mechanism must be validated against a
failure that actually happened — and it is also the proof the oracle works, because a
checker that never fires is indistinguishable from one that is switched off. We fixed the
fixture and never touched the assertion, and the most valuable artefact to carry forward is
the transaction-isolation oracle: a monotonic-counter model whose linearizability *is* the
lost-update check, red-proven by stripping the `FOR UPDATE` off the exact
`TryAcquireSchedulerLock` RMW shape and watching two increments both return the same value.

---

## Deliverables (paths)

- Seeded scheduler: `internal/testutil/schedfuzz/schedfuzz.go`
- Models + history: `fuzz/thirdparty/pools/kvmodel_test.go`
- Targets: `fuzz/thirdparty/pools/{sqlitepool,pgxpool,gormtx}_fuzz_test.go`
- Oracle red/green proofs: `fuzz/thirdparty/pools/oracles_test.go`
- targets.d confs: `scripts/fuzzing/targets.d/fuzz-thirdparty-pools__Fuzz{SQLitePool,PgxPool,GormTxn}Linearizable.conf` (+ regenerated `targets.conf`)
- Changelog: `CHANGELOG.md` v0.97.0 (was the fragment `fuzz-pool-schedule-race.md`, assembled at release)
- Invariant: `internal/storage/store/INVARIANTS.d/INV-STORE-gorm-txn-rmw-no-lost-update.md`
- This report (committed copy): `docs/fuzzing/sc1-pool-schedule-race.md`
