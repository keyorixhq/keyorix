- **INV-CORE-named-lock-section-survives-lock-loss** A `WithNamedLock` lock is not proof
  of exclusivity: when its connection dies, another replica can hold the same key for up to
  one liveness-ping interval plus its timeout before this holder's ctx is cancelled
  (docs/design/pooler-lock-loss.md). An invariant a named-lock section protects must
  therefore hold in the WRITE transaction itself: a constraint, a fused storage call that
  row-locks what its verdict reads, a conditional write, or a row-lock fence that every
  competing writer takes followed by a re-check through `tx`. Every call site is listed with
  its verdict in docs/design/named-lock-overlap.md. The user-deactivation paths (SuspendUser,
  UpdateUser, DeleteUser, UpdateSCIMUser, DeprovisionSCIMUser, MigrateUserToMachine) keep the
  last-admin invariant through `fenceLastAdminDeactivationOn` (grant rows FOR UPDATE, then
  `guardLastAdminDeactivationOn(tx)`), in the same lock order as `RemoveGlobalAdminRoleGuarded`.
  Why: NAMEDLOCK-OVERLAP-1. On main two such deactivations overlapping in the window
  stranded the install with zero admins.
  Guard: `TestNamedLockOverlap_EveryCallSiteIsInventoried` (internal/core/guards: a call site
  without a row, or a row without a call site, fails);
  `TestNamedLockOverlap_UserDeactivation_LastAdminSurvives` (the fake lock backend in
  `named_lock_overlap_harness_test.go`, one case per deactivation path);
  `TestNamedLockOverlap_SuspendUser_ConcurrentWriteTransactions_Postgres` (pg-gated, two
  replicas, both write transactions open). Not covered: the sites marked "needs check" or
  NEEDS ANDREI in that table, whose invariant still rests on the named lock alone.
<!-- section: Atomicity / transactions -->
