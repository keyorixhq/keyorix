- **INV-STORE-credential-insert-rechecks-owner** Every insert into the two tables a
  credential sweep covers — `personal_access_tokens` and `sessions` — happens inside a
  transaction that then re-reads the owning user with `lockLiveParent`
  (`requireLiveCredentialOwner`: still `is_active`, still in a login-capable
  `account_state`) and rolls back if it is not. That is all three inserts:
  `CreatePersonalAccessToken`, `CreateSession` and `RotateSession`. Why: #2701 — the
  sweeps (`setAccountState`'s blocked-state branch, `DeleteUser`,
  `DeprovisionSCIMUser`) row-lock the user and then revoke, but nothing serialized the
  inserts against them, so a credential minted in the window committed unrevoked after a
  sweep that was audited as complete; since `ReactivateUser`/`RestoreUser` revoke
  nothing, the routine suspend → investigate → reactivate sequence handed it back.
  **The precondition this rests on**: every sweep path row-locks the user BEFORE
  revoking, which is what makes `lockLiveParent`'s write-then-check ordering sound (see
  its own doc comment — a sweep that revoked children before touching the parent row
  would defeat it). The SQL `account_state` predicate deliberately reuses
  `globalAdminLiveAccountStates` — the same slice, not a copy — so
  `TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked` keeps it in step with
  `core.AccountLoginBlocked` and there is no second list to drift. Guard:
  `credential_owner_liveness_guard_test.go` `TestCredentialInsertsRecheckOwnerLiveness`
  (structural, with its population derivation written in) and `internal/core`
  `TestCTAReview_CreatePAT_vs_SuspendUser_CrossReplicaPostgres` /
  `TestCTAReview_CreateSession_vs_SuspendUser_CrossReplicaPostgres` /
  `TestCTAReview_CreatePAT_vs_DeleteUser_CrossReplicaPostgres` (pg-gated); the same
  interleavings on SQLite with the production DSN, `TestCredentialUnderSuspend_*_CrossReplicaSQLite`
  (default-ci); and `credential_owner_refusal_test.go`
  `TestCredentialInsertRefusedForUnusableOwner` (default-ci: every unusable owner state x
  all three inserts refuses and leaves no row, every login-capable state still mints).
  Consequence for fixtures: a test that mints a session or PAT needs a real, login-capable
  owner row; seed it per test (`seedCredentialOwners` here,
  `freshCoreS12WithCredentialOwners` in `server/http/handlers`), never inside a shared
  fixture that other tests count users against.
