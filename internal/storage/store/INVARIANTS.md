# internal/storage/store invariants

Read this before changing anything in `internal/storage/store` (the GORM-backed CRUD and
locking primitives `internal/core` calls). See `internal/storage/INVARIANTS.md` for the
factory/migration/schema-epoch layer above this one.

Format: `INV-STORE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Named locks (`WithNamedLock`)

- **INV-STORE-01** `WithNamedLock`'s reentrancy guard keys on `lockKey`, not "any lock held" —
  a nested call under a DIFFERENT key still acquires its own lock. Why: security-closures
  `FIX-5-namedlock`. Guard: `TestWithNamedLock_NestedDifferentKey_StillSerializesAgainstOtherHolder`.
- **INV-STORE-02** A reentrant `WithNamedLock` call under the SAME key does not deadlock
  (SQLite's non-reentrant mutex, Postgres's second-connection self-block). Why:
  `local_named_lock.go` doc comment, #1646 origin. Guard:
  `local_named_lock_test.go:TestWithNamedLock_ReentrantSameKey_DoesNotDeadlock`.
- **INV-STORE-03** The per-key lock registry reclaims (deletes) entries once no goroutine
  holds/waits on them — unbounded growth is a real regression. Why: #1690. Guard:
  `TestWithNamedLock_RegistryReclaimsEntriesAfterUse`,
  `TestWithNamedLock_ConcurrentSameKey_MutualExclusionSurvivesReclamation` (race-tested).
- **INV-STORE-04** A derived advisory-lock int64 key is stable and key-dependent — the same
  string always hashes identically, different strings don't collide in practice. Why:
  `namedLockKey` FNV-1a hashing. Guard: `TestNamedLockKey_StableAndKeyDependent`.
- **INV-STORE-05** Nesting distinct `WithNamedLock` keys inside one call chain reuses the
  outer call's single pooled Postgres connection rather than acquiring a second — avoids
  pool-exhaustion deadlock under small `max_open_conns`. Why: FIX-5 regression, reproduced
  against real Postgres with `MaxOpenConns(1)`. Guard:
  `local_named_lock_pool_exhaustion_test.go:TestWithNamedLock_NestedDifferentKey_DoesNotExhaustConnectionPool`.
- **INV-STORE-06** The same lock key across multiple real Postgres instances/processes
  genuinely serializes; different keys don't contend. Why: cross-replica advisory-lock
  requirement (ADR-039 HA). Guard: `concurrency_named_lock_postgres_test.go`
  (`TestConcurrency_WithNamedLock_MultiInstancePostgres_SameKeySerializes`,
  `_DifferentKeysDontContend`, pg-gated).
- **INV-STORE-07** `WithSchedulerLock` runs a scheduler tick on exactly one replica at a time
  via Postgres advisory lock (SQLite: always runs, re-entrant). Why: ADR-039. Guard:
  `concurrency_scheduler_lock_postgres_test.go:TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce`
  (pg-gated: 8 independent `LocalStorage` instances, own connection each, race one key —
  red, 8 of 8 run, when the `!locked` early return is disabled; #2508) and
  `local_scheduler_lock_test.go:TestWithSchedulerLock_SQLiteAlwaysRuns` (SQLite half).

## Break-glass

- **INV-STORE-08** Purge does not hard-delete a break-glass row mid-reconciliation. Why:
  security-closures `FIX-7-breakglass`. Guard:
  `TestDeleteExpiredBreakGlassBefore_ReconciledRowStillRevocable`.
- **INV-STORE-09** `reconcileBreakGlassIDsToExpired`'s UPDATE re-checks `state = 'active'` at
  write time (never trusts a stale Pluck'd ID list) — a concurrent revoke landing between read
  and write must not be silently overwritten back to 'expired'. Why: Part 2 regression audit
  doc comment in `local_purge.go`. Guard:
  `local_retention_test.go:TestDeleteExpiredBreakGlassBefore_ConcurrentRevokeBetweenPluckAndUpdate`
  (drives the real pluck → revoke → reconcile interleaving deterministically; red, state ends
  'expired', when the `AND state = ?` predicate is dropped; #2509).
- **INV-STORE-10** `DeleteExpiredBreakGlassBefore`'s reconcile-update-fails and final-delete-fails
  paths propagate errors correctly. Guard: `local_purge_cascade_sweep_test.go`
  (`TestDeleteExpiredBreakGlassBefore_ReconcileUpdateFails`, `_FinalDeleteFails`).
- **INV-STORE-11** Creating a second active break-glass activation for the same project+user
  is rejected; reactivation after the prior one is inactive is allowed; a concurrent race for
  the same project/user yields exactly one winner. Why: break-glass partial-unique-index
  invariant (see INV-STORAGE-13). Guard: `local_break_glass_test.go`
  (`TestCreateBreakGlassActivation_RejectsSecondActiveForSameProjectUser`,
  `_AllowsReactivationAfterPriorIsInactive`, `_DifferentProjectOrUserUnaffected`,
  `_ConcurrentRaceYieldsExactlyOneWinner`).
- **INV-STORE-12** Reading break-glass state never persists/mutates it as a side effect. Guard:
  `TestBreakGlassReads_NeverPersistState`.
- **INV-STORE-13** Reconciling an expired break-glass activation transitions only the matching
  row, leaves an already-revoked row alone, and no-ops on no match. Guard:
  `TestReconcileExpiredBreakGlassActivation_TransitionsOnlyTheMatchingRow`,
  `_LeavesRevokedRowAlone`, `_NoMatchIsNoop`.

## State-machine transitions (atomic conditional UPDATE pattern)

- **INV-STORE-14** `TransitionMachineIdentityState`/`TransitionSecretStatus` persist via a
  conditional `WHERE id = ? AND state/status = ?` + `Select("*")` + `Updates(m)` — the full
  mutated row is written in one statement, only when the row's current state still matches
  `fromState`. Why: #388; mirrors `UpdateProjectInvitation`'s shape; "atomic security counters"
  review-finding pattern applied to state machines. Guard: inferred live from
  `local_machine_identities.go:57` and `local_secrets.go:548` — dedicated test names not
  independently confirmed in this pass. UNGUARDED pending confirmation (#issue: locate and
  cite the exact test, or add one asserting a stale-fromState UPDATE affects 0 rows).
- **INV-STORE-15** `LockMachineIdentityForUpdate` takes `SELECT ... FOR UPDATE` on Postgres
  only (SQLite has no row lock, relies on single-process + transaction) — the two dialects'
  serialization strategy stays matched to `TransitionMachineIdentityState`'s usage, and the
  lock is always taken INSIDE the same `WithTransaction` the write uses (a standalone,
  unwrapped `FOR UPDATE` is a no-op on Postgres — confirmed historical test-only defect, see
  CLAUDE.md top-matter). Why: `local_machine_identities.go:32-37` doc comment, #388. UNGUARDED
  pending re-verification (#issue: re-confirm current test coverage wraps the lock+write in one
  transaction; the historical defect was in the TEST harness, not production, but re-check on
  every future change to this call site).
- **INV-STORE-16** Per-secret and per-grant `max_reads` counters never exceed their cap even
  under concurrent reads — atomic conditional UPDATE, fail closed. Why: "atomic security
  counters" review-finding pattern. Guard: `concurrency_max_reads_test.go`
  (`TestConcurrency_MaxReads_NeverExceedsCap`, `TestConcurrency_MaxReadsSecretLevel_NeverExceedsCap`).

## Soft-delete / purge races

- **INV-STORE-17** Restoring a soft-deleted row and a concurrent purge racing the same row do
  not produce inconsistent state — restore wins the race. Guard:
  `concurrency_purge_restore_race_test.go`
  (`TestConcurrency_PurgeDeletedSecretsBefore_RestoreWinsRace`,
  `_PurgeDeletedUsersBefore_RestoreWinsRace`, `_PurgeDeletedProjectsBefore_RestoreWinsRace`).

## GORM hook / timezone correctness (`internal/storage/models`, `store`)

- **INV-STORE-18** A raw `.Update()`/`.Updates()`/`.UpdateColumn()`/`.UpdateColumns()` call
  targeting a column a `BeforeSave` hook owns never bypasses that hook — enumerated by AST
  derivation from `models.go`, not a hand list; raw `db.Exec` SQL strings are explicitly NOT
  covered by this scanner (stated boundary, not a silent gap). Why: #1619. Guard:
  `internal/storage/models/g1619_beforesave_bypass_guard_test.go` (bypass-site scanner; exact
  top-level `func Test...` name not isolated in this pass — confirm before citing a specific
  function).
- **INV-STORE-19** Every field a `BeforeSave` hook maintains (UTC normalization etc.) has its
  hook actually exercised, and every time column queried via range (`<`, `>`, `BETWEEN`) is
  tracked as needing UTC normalization — no untracked range-queried time column. Why: G81
  timezone-normalization class (GORM/SQLite timezone mismatch). Guard:
  `g81_guard_test.go` (`TestG81_MaintainedFieldsHaveWorkingHooks`,
  `TestG81ScannerDetectsRangeQueriedColumns`, `TestG81_NoUntrackedRangeQueriedTimeColumns` —
  AST-derived scanners, not hand lists).
- **INV-STORE-20** Audit-event timestamps (and dynamic-lease timestamps) are stored and
  queried correctly even when the application layer hands in a non-UTC `time.Time`. Why: same
  G81 class. Guard: `g81_audit_event_timezone_test.go`
  (`TestLogAuditEvent_NonUTCEventTimeStoredAsUTC`,
  `TestVerifyAuditChain_ValidatesRowWithNonUTCEventTime`,
  `TestGetAuditLogs_RangeQuery_FindsRowWithNonUTCEventTime`); sibling
  `g81_dynamic_lease_timezone_test.go` (same class, not individually re-read).
