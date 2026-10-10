- **INV-STORE-project-row-lock-unscoped** Both sides that can change a project's own
  `deleted_at` — `deleteProjectCascade` (via `lockProjectRowForCascade`, shared by
  `DeleteProject` and `DeleteProjectIfEmpty`) and `RestoreProject` — row-lock the project
  **by id, UNSCOPED, before touching any child**, and the cascade reads its liveness verdict
  off the row it just locked rather than folding `deleted_at IS NULL` into the locking query.
  Why: #2723/#2724 — the defect was not a missing lock. #2656's `FOR UPDATE` was there, but
  written with GORM's default scope, which appends `deleted_at IS NULL`; on an
  already-deleted project it matched zero rows and locked **nothing**, which is exactly the
  case where a concurrent `RestoreProject` must be excluded. Every other cascade statement is
  `deleted_at IS NULL`-scoped too, so under READ COMMITTED the sweeps skipped (their
  snapshots saw deleted children), the restore committed, and the cascade's final
  `UPDATE projects` took a fresh statement snapshot, saw the project live and deleted it —
  leaving every restored environment and secret live under a deleted project, a state no
  serial order produces. **A lock with no row to take is not a lock, and it looks exactly
  like one**; this is the general lesson, not a GORM quirk.
  Guard: `project_row_lock_guard_test.go` `TestProjectRowLocks_AreUnscoped` (default-ci),
  which checks `Unscoped()` specifically — a guard asserting only "takes `clause.Locking`"
  would have been green for the bug's entire lifetime — plus
  `TestDeleteProjectEntryPointsGoThroughTheSharedCascade`, which pins the premise that
  locking in the shared cascade covers both delete entry points (#528). Behavioural,
  pg-gated: `internal/core/concurrency_restore_project_vs_delete_postgres_test.go`
  `TestCTAReview_DeleteProject_WaitsForARestoreHoldingTheProjectRow_Postgres`.
  **Not covered, deliberately**: no end-state ("project deleted AND live children") test
  exists. One was written and deleted — with the fix reverted it never reproduced the orphan
  state, failing only on its own non-vacuity floor. A deterministic version is impossible by
  construction rather than merely hard: the interleaving needs the restore to COMMIT inside
  the cascade, which a one-shot hook can arrange only for the BROKEN code, since after the
  fix the cascade holds the project row from its first statement and the hooked restore would
  block inside the cascade's own callback and hang. The mechanism (mutual exclusion on the
  row) is asserted instead of the forbidden state. See that file's header.
  **Second path in #2724, left open**: `RestoreProject` does not take
  `EnvironmentSecretGuardLockKey`, so in principle `DeleteEnvironment`'s count-then-delete
  pair could straddle a restore. Its precondition is a LIVE environment under a DELETED
  project — `DeleteEnvironment`'s own `Delete` is default-scoped and errors "environment not
  found" on an already-deleted row, and the cascade's env sweep leaves none live — and that
  state is what #2702/#2710 produce and #2881 closes. So this rests on #2881; it is recorded
  rather than fixed here, and taking N environment locks would additionally require making
  the `environment-secret-guard` family `Nestable` in `storage.NamedLockOrder`.
