# FSPG — Real PostgreSQL fault-injection coverage

Task FS-PG / session FSPG. Branch `fuzz/fspg-postgres-real-faults`, clone on pve01.
Live document; a copy is committed at `.scratch/REPORT.md`. No production-code
changes (the whole deliverable is a new test-only package).

**Most reasonable reading of the task** (stated up front, nobody to ask): the
named backlog file `claude/2026-09-18-fuzzer-backlog-not-yet-implemented.md` does
**not exist** in this clone (no `claude/` dir; only `BACKLOG.md` / `web/BACKLOG.md`
exist, neither mentions I2/fs1). I proceed from the task prompt itself, which is
self-contained: close the PostgreSQL real-fault gap with the same oracle shape as
`scripts/powercut` (no acknowledged commit lost, no torn version, audit chain
intact after recovery).

Status: **harness built and green against the real shared PostgreSQL server;
oracles red-proved; fuzz target registered; invariant + changelog fragments
added.** Fuzz/fault soak logged in §9.

---

## Environment facts (verified)

- **No PostgreSQL server binaries on this host.** `initdb`, `pg_ctl`, `postgres`,
  `psql`, `pg_config` all MISSING (checked PATH, `/usr/lib/postgresql`, `/opt`, a
  full-filesystem `find`). The `pg*` entries in `/usr/bin` are netpbm graymap
  tools, not PostgreSQL. **Consequence: fault classes (b) ENOSPC/read-only-FS and
  (c) crash-of-a-throwaway-cluster are NOT implementable here** — both require a
  throwaway cluster I start myself and I cannot `initdb` one. Documented as
  deferred with the exact blocker (§10), not silently skipped. **Only class (a) —
  connection-loss at protocol points, via a TCP fault proxy — is implemented.**
  The proxy touches no server process, satisfying the hard safety rule.
- **Shared PG (CT 270):** DSN is URL form, `scheme=postgres host=192.168.10.34
  port=5432 dbname=difffuzz` (non-secret fields only; user/password never printed
  or committed; sourced from `/mnt/data/wave4/w4-chunks.env`). Plaintext wire
  (`sslmode=disable`) ⇒ the proxy can cut at **PostgreSQL protocol-message
  boundaries**, not just arbitrary byte offsets.
- **Safety:** every database I create is named `fspg_<pid>_<n>` (via
  `pgdsn.IsolatedDatabase`, prefix `fspg`), dropped on cleanup `WITH (FORCE)`.
  I never stop/restart/signal the shared server; I only CREATE/DROP `fspg_*`
  databases and connect to run statements.
- **dm-flakey / device-mapper: SKIPPED** by rule (needs root device-mapper ops
  affecting host devices); the existing `scripts/powercut/run-dmflakey.sh` already
  owns that SQLite-only path.

---

## STEP 1 — Are FuzzStorageFaultOperations & friends run against PostgreSQL in CI today?

**Answer: Yes — the `server/faultops` *seed corpus* (plain `go test`, not `-fuzz`
mutation) runs against a real PostgreSQL service container in CI — but ONLY as an
*interface-level mock* fault. There is NO real PostgreSQL-level fault coverage.
That real-fault gap is what this task closes.**

Evidence (file:line):

1. `server/faultops/world_reuse_test.go:193-247` (`openWorldDBTB`): the fault
   world is SQLite unless `KEYORIX_TEST_PG_DSN` is set; when set, every world for
   the run uses a fresh Postgres schema. `server/faultops/world_test.go:56-60`
   documents this gate.
2. The `test-suite:` job (`.github/workflows/ci.yml:1287`) sets
   `KEYORIX_TEST_PG_DSN` **at job level** (`ci.yml:1646-1647`), and its matrix
   includes legs `faultops-1`…`faultops-5` (`ci.yml:1489-1506`) which run
   `./server/faultops` (`ci.yml:1830`). So `go test ./server/faultops` — which
   executes `FuzzStorageFaultOperations` and the other `Fuzz*`/`Test*` with their
   **seed corpus** (no `-fuzz`) — runs against real Postgres in the merge queue
   and on push-to-main. Cross-confirmed by `pg-race-tests.yml:42-44`: "test-suite
   job sets KEYORIX_TEST_PG_DSN job-wide (all 21 legs, Postgres service
   container)". (The separate comment at `ci.yml:991` — "This job never sets
   KEYORIX_TEST_PG_DSN" — is a DIFFERENT job, the closure-guard job, not
   test-suite.)
3. **But the fault itself is a mock.** `server/faultops/world_test.go:183-184`
   wraps the real backend in `faultstorage.NewFaultyStorage(real, spec)`. Faults
   are injected at the **Go storage-interface layer** (`internal/faultstorage`,
   generated `faulty_storage_generated.go`) — a method returns a synthetic error,
   panics, or applies effect-then-error. The *backend* is Postgres but the *fault*
   is identical to the SQLite case: it never exercises the PostgreSQL wire
   protocol, a dropped TCP connection, an ambiguous COMMIT, disk-full, or
   crash-recovery.

So the mock path runs on PG in CI (good), but "real PostgreSQL fault coverage"
(the enterprise durability story) did not exist. `scripts/powercut` is the only
real-fault tool and it is **SQLite only** (`scripts/powercut/main.go:1-27`,
`cfg.Storage.Type = "local"`). Class (a) below adds the real connection-loss case
for PostgreSQL.

---

## STEP 2 — What was built

New **test-only** package `server/pgfault/` (every file is `_test.go`; no
production code is built from it):

- `proxy_test.go` — a single-upstream TCP fault proxy that frames PostgreSQL v3
  wire messages (untyped StartupMessage + typed messages) and, when armed, cuts
  (`faultCut`) or stalls-then-cuts (`faultStall`) the Nth typed message in a
  chosen direction: **frontend** (client→server, where COMMIT/Sync is sent) or
  **backend** (server→client, where the commit ack / ReadyForQuery returns — the
  ambiguous-commit window). A 64 MiB per-message cap (`maxPGMessage`) bounds
  allocation on a corrupt length.
- `world_test.go` — wires the proxy in front of the real server and drives
  keyorix's production audit-commit path `store.LocalStorage.LogAuditEvent` (the
  same hash-chained, group-committed path `scripts/powercut` exercises on SQLite;
  `internal/storage/store/local_audit_chain.go`). Each test gets a throwaway
  `fspg_<pid>_<n>` database (dropped on cleanup), a proxied write handle, and a
  DIRECT verification handle that never sees the fault.
- `commit_oracle_test.go` — the durability oracles (§3) plus `TestPGFault_ConnectionCut`
  (cuts at 6 protocol points × 2 directions over a 24-commit burst) and
  `TestPGFault_StallThenCut` (stalls past the client deadline, the ambiguous
  stall).
- `redproof_test.go` — three red-proofs (§5).
- `fuzz_pg_fault_commit_test.go` — `FuzzPGFaultCommit`: fuzzes the fault spec
  (mode, direction, Nth message, burst size) and asserts the same oracles, with
  per-input time and allocation bounds (§6).

Registration / hygiene:
- `scripts/fuzzing/targets.d/server-pgfault__FuzzPGFaultCommit.conf` (new file,
  not an append) + regenerated `scripts/fuzzing/targets.conf`
  (`gen-targets-conf.sh --check` green).
- Invariant `INV-PGFAULT-acked-commit-survives-cut`
  (`server/pgfault/INVARIANTS.d/`, package `INVARIANTS.md` declaring the prefix,
  index link in `docs/INVARIANTS.md`); `internal/statemap` fragments guard green.
- `changelog.d/fspg-postgres-real-faults.md` (`changelog-assemble.sh --check`
  green).

## 3. The oracles — and exactly what each does NOT verify

Mirrors `scripts/powercut/main.go`'s SQLite oracle, restated for a wire cut on
PostgreSQL:

- **ORACLE 1 — no acknowledged commit is lost.** Every `LogAuditEvent` that
  returned nil is present after reconnect (read back on the DIRECT handle). A TCP
  fault can error only the ONE in-flight commit; it can never unmake an
  already-acknowledged one. *Does NOT verify:* durability across a real
  OS/postmaster crash (class c, not runnable here) — "acknowledged ⇒ durable" is
  PostgreSQL's own fsync guarantee; this oracle checks the client-side cut does
  not defeat it, not that fsync is honoured on lying hardware.
- **ORACLE 2 — chain intact / no torn row.** `VerifyAuditChain` passes after the
  fault: no half-written row, no broken hash link. *Does NOT verify:* any table
  other than `audit_events` (only the audit path is driven; secret-version
  tearing is argued from PostgreSQL MVCC row-atomicity, not separately driven —
  §10).
- **ORACLE 3 — an ambiguous commit is never a false success.** The forbidden
  quadrant is acknowledged-but-absent. A present-but-unacknowledged row (server
  committed, ack lost in the cut) is the legitimate ambiguous window and is
  ALLOWED — the client correctly saw an error, not a false success. Checked as
  the contrapositive of Oracle 1 (acked ⇒ present). *Does NOT verify:* retry
  idempotency of a non-idempotent op — `LogAuditEvent` appends unconditionally,
  so the task's "a retried idempotent op does not duplicate" sub-oracle is NOT
  exercised here; it needs an op with a uniqueness constraint (§10).

The harness also asserts **no panic / transport breakage**: a cut must surface as
an ordinary Go error to the caller, never a panic.

Also NOT verified (honesty): behaviour under disk-full / read-only FS (class b);
a lying NIC or mid-byte corruption (the proxy models a clean TCP close/stall);
and keyorix *distinguishing* ambiguous from definite failure (it returns a single
error either way — the oracle enforces only the one-directional "acked ⇒ present"
guarantee that distinction would need, not a richer taxonomy).

## 4. Reachability of the exercised code

The harness drives the **real `store.LocalStorage.LogAuditEvent` /
`VerifyAuditChain`** that production `internal/core` calls on every authenticated
mutation (it is the batched group-commit audit path;
`scripts/powercut/main.go:8-9` and `internal/storage/store/local_audit_chain.go`
confirm). This is a live-caller path driven over a real PostgreSQL backend, not a
lower-layer-only SQL repro — so any finding here would be application-reachable,
not a storage-layer-only demonstration.

## 5. Red-proofs (a guard nobody has watched fail is not a guard)

All three go red on a planted violation and green otherwise; the planted defect
lives in the fault's own effect surface (the audit rows), never in production
code (RULES):

- `TestPGFault_RedProof_FaultIsLoadBearing` — proves the cut actually interrupts
  a commit: a backend-ack cut during a 19-commit burst left **18/19 acked** (one
  interrupted), so the oracle sweep is not vacuously green. Fails if no cut ever
  leaves a commit un-acknowledged.
- `TestPGFault_RedProof_OracleDetectsLostAck` — deletes one ACKNOWLEDGED row and
  confirms Oracle 1 flags exactly that index as a lost acknowledged commit.
- `TestPGFault_RedProof_OracleDetectsBrokenChain` — tampers a committed row's
  payload without recomputing its hash and confirms Oracle 2 reports the chain
  invalid.

Observed (real run): all green; logs "cut backend n=1: 18/19 commits acked",
"flagged planted lost acked commit 12", "chain reported invalid after planted
tamper".

## 6. Resource bounds per input (bounded time + allocations)

`FuzzPGFaultCommit` enforces, per input:
- **Time:** every commit carries a short context deadline (`perCommitFuzz` =
  1.5 s), the burst length is bounded (`maxBurst` = 32), stall duration is a fixed
  small `stallForFuzz` = 2 s, and the whole input is asserted to finish within
  `maxInputWall` = 25 s — so a stall fault cannot hang an input.
- **Allocations:** the proxy's per-message read is capped at `maxPGMessage`
  (64 MiB) so a corrupt length never drives an unbounded allocation, and the
  input's own `runtime.MemStats.TotalAlloc` delta is asserted under
  `maxInputAlloc` = 256 MiB.
- **Connections:** the proxied pool is capped at 1 connection; the throwaway
  `fspg_` database is reused across inputs (truncated), so the fuzzer does not
  create a database per input.
Throughput is intentionally low (each input runs real remote commits and, for
stall inputs, a real timeout against a remote server) — this is a soak target,
not a high-exec one. The bounds above keep each input's cost finite.

## 7. What ran (evidence)

Environment: `GOMAXPROCS=2`, `nice -n 10`, caches under `/mnt/data/wave7/fspg`,
`KEYORIX_TEST_PG_DSN` sourced from `/mnt/data/wave4/w4-chunks.env` (never
printed/committed). Shared server CT 270; only `fspg_`-prefixed databases
created/dropped; server process never signalled.

- `go vet ./server/pgfault/` — clean.
- `TestPGFault_Smoke` — PASS (10/10 acked, 10 present, chain valid).
- `TestPGFault_ConnectionCut` — PASS. `TestPGFault_StallThenCut` — PASS.
- `TestPGFault_RedProof_*` (×3) — PASS (logs in §5).
- `FuzzPGFaultCommit` 30 s probe — PASS, oracles held on every input.
- `internal/statemap` fragments guard — PASS. `changelog-assemble.sh --check` —
  PASS. `gen-targets-conf.sh --check` — PASS.
- Long soak: §9.

## 8. Findings in keyorix

**None.** The harness confirms the durability property *holds* for the
audit-commit path under real connection-loss at every swept protocol point,
including the ambiguous-commit window — this is a coverage/assurance deliverable,
not a bug report. Honest classification: no VULNERABILITY / CANDIDATE /
SECURITY-DEFECT / DEFECT observed. If the soak surfaces an acknowledged-but-absent
row or a broken chain, it will be minimized, replayed 3×, and classified here with
a reachability trace to a live caller before any claim about keyorix.

## 9. Soak log

(updated as foreground fuzz chunks complete)

## 10. LEFTOVERS

- **Classes b and c (disk-full / read-only-FS / crash-recovery)** need a local
  throwaway cluster (`initdb`/`pg_ctl`), absent on this host. On a host with
  PostgreSQL binaries: `initdb` a cluster on a size-limited tmpfs under the
  session dir, inject 53100/57P01/40001/40P01 and `kill -9` the postmaster during
  a write burst, same oracles. The proxy is reusable as-is for the statement-level
  SQLSTATE variants.
- **Secret-version tearing & retry idempotency** are currently argued from MVCC
  row-atomicity, not separately driven. Follow-up: drive `CreateSecretVersion`
  through the proxy, assert no torn version row and that a retried create respects
  the `(node_id, version)` uniqueness constraint — this closes the task's
  "retried idempotent op does not duplicate" sub-oracle that the append-only audit
  path cannot exercise.
- **Multi-statement application transactions** beyond the audit path (the
  `WithTransaction`-wrapped CreateSecret/CreateUser flows) are not yet driven
  through the proxy; the audit path was chosen first as the cleanest durability
  oracle and the one `scripts/powercut` already models.
- **STEP-1 nuance for a future reader:** faultops *does* run on PG in CI, but
  mock-only; if real-fault coverage is later wanted in the merge queue, this
  package is PG-gated and low-throughput — wire it into a nightly, not a per-PR
  leg.
