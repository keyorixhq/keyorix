- **INV-CORE-role-update-keep-scope-never-written-back** An `UpdateRole` that keeps the
  stored assignable scope (`AssignableScope == ""`) never writes that column: the `""` is
  passed through to `storage.UpdateRole`, which leaves `assignable_scope` out of its
  UPDATE. The scope core reads in the transaction only classifies the update (widening
  or not, the audit text); it is never written back, so a narrowing another replica
  commits after that read (plain `GetRole`, no row lock, READ COMMITTED) survives, and
  the keep-scope update's audit row names no scope change because it made none. This is
  INV-CORE-42's "a write that persists a pre-read snapshot must not overwrite columns the
  operation did not change", applied to the role row. Why: #3909 (found reviewing #3880;
  REVIEW-3585-DEEP-1 F4 had fixed the same stale write-back between the two commits of a
  split update, not within one). Guard: pg-gated, two independent pools,
  `cta_review_update_role_keep_scope_postgres_test.go:TestCTAReview_UpdateRoleKeepScope_vs_NarrowScope_CrossReplicaPostgres`
  (replica B's narrowing runs from a GORM callback on replica A right before A's UPDATE;
  asserts the stored scope and both audit rows); default-ci store half
  `internal/storage/store` `TestUpdateRole_EmptyAssignableScopeKeepsStoredScope` (SQLite,
  and Postgres with a DSN). Since #3919 each UpdateRole transaction reads the role it
  classifies with `tx.LockRoleForUpdate` (FOR UPDATE on Postgres) as its first statement, so
  an EXPLICIT scope change is classified (widening: fail closed; narrowing: owed) and audited
  ("a -> b") from the row it actually replaces: a concurrent update of the same role waits.
  Guard: `cta_review_updaterole_explicit_scope_postgres_test.go:TestCTAReview_UpdateRoleExplicitScope_vs_NarrowScope_CrossReplicaPostgres`
  (pg-gated, the audit rows must chain from the initial scope to the stored one),
  `internal/core/guards` `TestUpdateRole_ClassifiesFromALockedRead` (no `tx.GetRole`, one
  locked read per transaction), `internal/storage/store` `TestLockRoleForUpdate_DialectMatchedLocking`.
  **Not covered**: between commit 1 and commit 2 of a split update a concurrent change can
  still land (commit 2 re-reads under the lock and names it, and is fail closed anyway); an
  explicit scope or description is last writer wins; SQLite cannot interleave here (BEGIN
  IMMEDIATE), so it is not part of the race test.
