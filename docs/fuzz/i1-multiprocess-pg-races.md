# I1 — Multi-process cross-replica PostgreSQL race fuzzing (MP1)

Branch: `fuzz/multiprocess-pg-races`. Harness: `scripts/e2e/mp1/`.
Report owner: task I1 / continuation I1C (2026-11-15).

## Reasonable-reading decisions (nobody to ask)

- **Report location.** The runtime rules named `/mnt/data/wave4/out/i1c-REPORT.md`,
  which is outside this session's sandbox (writes blocked). The continuation
  instruction directs the report to `docs/fuzz/i1-multiprocess-pg-races.md` and to
  commit it; that path is used here.
- **Database prefix.** The committed harness created `mp1_<pid>_<n>` databases. The
  I1C runtime rules require every database this session creates to be prefixed
  `i1c_`. Changed to `i1c_mp1_<pid>_<n>` so the harness can only ever create/drop
  its own databases on the shared host. Only these databases are touched; each is
  dropped on package teardown (`WITH (FORCE)`).
- **Serial-equivalence oracle.** The repo has no porcupine checker. Oracle #2 uses
  the sound single-register necessary condition (the surviving converged value must
  be one some acknowledged write set) rather than a full linearizability model. This
  is stated as a limitation below.
- **Shared PG host.** `KEYORIX_TEST_PG_DSN` points at a shared Postgres (database
  `difffuzz`). The harness never writes into that database; it `CREATE DATABASE`s its
  own `i1c_mp1_*` and connects the replicas there.

## The harness

`scripts/e2e/mp1/` boots `sharedReplicaCount = 3` real `keyorix-server` OS
processes (built once via `harness.BuildBinaries`) against ONE freshly-created
`i1c_mp1_*` PostgreSQL database — the ADR-039 HA shape: stateless replicas, no
leader election, one shared Postgres holding sessions, secrets, the audit chain and
the advisory locks. Replica 0 runs the full fresh-install sequence (admin init →
splice postgres config → encryption init → migrate → boot → `POST /system/init`);
replicas 1..n copy replica 0's key material (shared KEK/DEK), pick their own
loopback port, and boot only. Each replica has its own config dir, HOME, connection
pool and log file — the only shared state is the database.

Distinct from the in-process cross-replica fuzzers already in the tree
(`FuzzCrossReplicaInvariants`, `FuzzCrossReplicaOps`, the schedule-race fuzzer),
which run "replicas" as goroutines inside one process sharing one `Storage` object.

Requires `-tags e2e` and `KEYORIX_TEST_PG_DSN`. Tag-less runs hit skip stubs
(`fuzz_noe2e_test.go`) so the two fuzz targets stay listable for the CI
fuzz-targets guard without booting a cluster.

## Oracles, soundness, and what each does NOT verify

| # | Oracle | Test | Fuzz target | Red proof |
|---|--------|------|-------------|-----------|
| 1 | Uniqueness: concurrent same-name creates → exactly one winner + one active row | `TestUniqueNameExactlyOneWinner` | `FuzzMP1UniqueCreate` | `TestRedProof_Uniqueness` (pure) + `TestRedProof_UniquenessLive` (real constraint) |
| 2 | Serial equivalence (single-register necessary condition) | `FuzzMP1MultiProc` | `FuzzMP1MultiProc` | `TestRedProof_SerialEquivalence` |
| 3 | Post-return visibility (values); revoked PAT denied cross-replica within 30s window | `TestVisibilityWindow`, `TestRevokedPATDenied` | — | `TestRedProof_Convergence`, `TestRedProof_RevokedPATLive` |
| 4 | Advisory-lock exclusion: killed replica leaves no stuck lock | `TestKilledReplicaNoStuckLock` | — | (see limitations) |
| 5 | Audit chain valid + gap/fork-free; exactly one audit row per acknowledged op | `TestAuditChainVerifies`, `TestAuditCountExactlyOne` | — | `TestRedProof_AuditCount` |
| 6 | Kill + restart: survivors keep serving; killed replica reopens store with no hand repair | `TestKilledReplicaNoStuckLock` (restart half) | — | — |

### What each oracle does NOT verify

- **#1 Uniqueness.** Does NOT verify uniqueness for non-ASCII / Unicode-folded names
  (the harness generates simple ASCII names and counts active rows by exact `name`
  match, deliberately avoiding dependence on the folding implementation — see NFC/NFD
  note in CLAUDE.md). Does NOT verify uniqueness of any resource other than projects.
  Does NOT assert a specific conflict status code (only that exactly one is 2xx and
  the DB ends with one active row); a 5xx under load IS flagged.
- **#2 Serial equivalence.** Only a single-register necessary condition on secret
  VALUE convergence — NOT a full linearizability (porcupine) check over a multi-key
  history. It cannot detect an ordering violation that still lands on an
  acknowledged value (e.g. a stale-but-acknowledged value winning when a later write
  also acknowledged). It verifies "no torn/phantom/failed-write value survives" and
  "all replicas converge", not "the history is linearizable".
- **#3 Visibility / revocation.** Value visibility is bounded at 2s (far below the
  30s auth window, since values are not cached cross-replica). The PAT-revoke oracle
  asserts denial WITHIN the documented 30s positive-auth-cache window — it does NOT
  assert immediate denial, by design (CLAUDE.md: never assert across a documented
  staleness window). Does NOT cover session or role-suspension revocation paths
  (only PAT revoke is driven). Does NOT verify negative-cache behaviour.
- **#4 Advisory-lock exclusion.** Verifies the KILLED-replica half (a SIGKILLed
  backend's torn-down connections do not leave a session advisory lock held, so
  survivors keep committing audit appends within a bound). It does NOT drive two
  replicas into the SAME single-writer critical section (key rotation / migration /
  scheduler singleton) simultaneously and prove they mutually exclude — that
  "never run twice at once" half is UNVERIFIED by a positive concurrent-contention
  test here (the `configExtra(anomalySchedule)` hook exists for a scheduler-singleton
  oracle but no such oracle is wired). See Limitations / follow-ups.
- **#5 Audit.** `TestAuditChainVerifies` checks the chain is VALID via
  `admin verify-audit --pg-dsn`; `TestAuditCountExactlyOne` checks exactly one
  `secret.created` row per acknowledged create. Does NOT verify audit counts for
  update/rotate/delete event types (only `secret.created`). Does NOT independently
  re-implement chain verification — it trusts `admin verify-audit`.
- **#6 Kill + restart.** Restarts ONE replica (the SIGKILL victim) and confirms it
  becomes healthy and serves one authenticated write. Does NOT test a full-cluster
  cold restart, nor kill during migration, nor repeated kill/restart cycling.

## Status — COMPLETE

### Committed (branch `fuzz/multiprocess-pg-races`)
- `1701ab411a` — oracle code (uniqueness, audit-count, restart half; i1c_ DB prefix)
- `ea0584776b` — the six MP1 invariants + docs index row
- `8619dbac50` — fuzz target confs + changelog fragment
- report commit hash appended at the very end of this file.

(The first three MP1 commits — `52c22416bf`, `ac77949432`, `39ddf276b8` — landed in
an earlier session and carry the base harness: `cluster_test.go`,
`cluster_fuzz_test.go`, `oracles_test.go`, `redproof_test.go`.)

### Live oracle verification (all PASS, real 3-replica cluster on Postgres)
| Test | Result | Evidence |
|------|--------|----------|
| `TestUniqueNameExactlyOneWinner` | PASS | one 201 + two 409, 1 active row, ×3 trials |
| `TestVisibilityWindow` | PASS | update propagated to all replicas in 25 ms (bound 2 s) |
| `TestRevokedPATDenied` | PASS | revoked PAT denied on every replica within 0–1 ms (window 30 s) |
| `TestRedProof_RevokedPATLive` | PASS (32.4 s) | never-revoked token stays accepted the full window → oracle non-vacuous |
| `TestAuditChainVerifies` | PASS | `verify-audit` verdict VALID after concurrent burst |
| `TestAuditCountExactlyOne` | PASS | 9 acknowledged creates → each exactly 1 `secret.created` row |
| `TestKilledReplicaNoStuckLock` | PASS (18 s) | survivor wrote 18 ms after SIGKILL; victim restarted, reopened store, served a write; chain still VALID |
| `TestZZCanaryNoSecretInLogs` | PASS | 17 distinct secret values + key bytes, 0 hits in 3 replica logs |
| `TestRedProof_UniquenessLive` | PASS | duplicate create rejected, still exactly 1 active row |
| Both fuzz targets' seed corpora | PASS | convergence + serial-equivalence hold on all seeds |

### Pure red proofs (no PG) — all PASS
`TestRedProof_{Uniqueness,AuditCount,Convergence,SerialEquivalence,Canary}` — each
fires red on a planted violation (two winners / duplicated or dropped audit row /
divergent reads / torn surviving value / leaking log) and green on the good case.

### Fuzzing (foreground, 540 s chunks, `GOMAXPROCS=2 -parallel 2 nice -n 10`)
| Family | Chunks | Real time | ~execs | Corpus grew to | Crashes |
|--------|--------|-----------|--------|----------------|---------|
| `FuzzMP1UniqueCreate` (oracle #1) | 7 × 540 s + 1 × 110 s | ~65 min | ~334k | 295 interesting | 0 |
| `FuzzMP1MultiProc` (oracle #2/#3) | 7 × 540 s | ~63 min | ~162k | 209 interesting | 0 |
| **Total** | **15 chunks** | **~128 min** | **~500k** | — | **0** |

Every chunk ended `PASS`; no reproducer was written under `testdata/fuzz/`; no
`FAIL`/`panic` in any chunk log. Both families far exceed the 8-min-per-family
floor and the run exceeds the 120-min total floor.

### Environmental notes
- CPU temp file (`/sys/.../temp1_input`) is blocked by the session sandbox — relied
  on `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2` for thermal safety; no thermal
  throttling observed (throughput steady 40–175 execs/s).
- A stray gitignored `.scratch/clone/` (a full repo copy another session left here)
  makes the `internal/statemap` invariants-fragments guard red LOCALLY by
  double-counting every `INVARIANTS.md`. Not my change, does not ship (CI checks out
  clean), and no `scripts/e2e/mp1` real-tree error appears — my six fragments are
  well-formed and indexed.
- The git-write-guard lock was held by a dead prior session for the first ~40 min of
  this session (it never refreshed); I ran the required fuzzing during that window
  (no git needed) and committed the instant the 3-hour staleness threshold passed.
  The source files were verified-sound and resident in the worktree throughout, so
  nothing was at risk of loss.

## Findings

**No defects found.** Across ~128 minutes of real multi-process fuzzing (~500k
executions) and the full live oracle suite, every cross-replica HA invariant held:
exactly-one-winner uniqueness, value convergence / post-return visibility,
single-register serial equivalence, 30-s-bounded PAT-revoke propagation, a gap/fork-
free audit chain with exactly one row per acknowledged op, advisory-lock release on
SIGKILL, and clean store reopen on restart. No secret value or key byte leaked to a
log. No `5xx` was observed under any concurrent interleaving.

Findings table:

| ID | Classification | Oracle | Status |
|----|----------------|--------|--------|
| — | (none) | all | No violation observed in ~500k execs + live suite |

This is evidence of absence over the exercised surface, not proof of absence; the
"what each oracle does NOT verify" section above bounds the claim.

## Issue #4071 reproduction attempt

**Result: not reproduced.** #4071 is opened by `scripts/ci/failure-issue.sh` from the
nightly `pg-race-tests.yml` job, which runs the **in-process** `FuzzCrossReplicaInvariants`
(goroutine "replicas" over one shared `Storage`), not this multi-process harness. It
failed once on 2026-11-09 and went green afterwards, cause undiagnosed; the failing
seed is not recorded in the tree, so an exact byte-for-byte replay is not possible
from here.

This harness is a **stronger, independent** check of the same HA properties — real
OS processes, separate connection pools and per-process caches, the only shared state
being Postgres. Driving it for ~128 min / ~500k concurrent interleavings plus the full
live oracle suite produced **zero** cross-replica violations. That does not diagnose
#4071, but it is positive evidence that the cross-replica invariants (uniqueness,
convergence, audit-chain integrity under multi-writer load, advisory-lock release)
hold under a harsher concurrency model than the one that flaked. The most likely
reading, consistent with "flaked once then green," is a transient/environmental
hiccup in the nightly rather than a latent correctness defect — but this is a
probabilistic inference, not a root cause. Recommended follow-up (issue-ready): have
`failure-issue.sh` attach the failing fuzz seed/corpus entry to the issue so a future
run can replay the exact input; without it, these failures are structurally
undiagnosable after they go green.

## Follow-ups (issue-ready, no production change made)

1. **Advisory-lock exclusion, positive half (oracle #4 gap).** This harness proves a
   SIGKILLed replica releases its session advisory lock, but does NOT drive two
   replicas into the same single-writer critical section (key rotation / migration /
   scheduler singleton) at once and assert mutual exclusion. The
   `configExtra(anomalySchedule)` hook was added for a scheduler-singleton oracle but
   no such oracle is wired. Proposed: a `TestSchedulerSingleton` that boots N replicas
   with a tight `anomaly_alerts.schedule` and asserts (from the audit/DB side) the job
   body executes once per tick, not N times. Classification: HARDENING (coverage gap),
   not a known defect.
2. **#4071 undiagnosability.** As above — attach the failing seed in `failure-issue.sh`.
3. **Audit count beyond `secret.created`.** `TestAuditCountExactlyOne` covers creates
   only; extend to update/rotate/delete event types.
