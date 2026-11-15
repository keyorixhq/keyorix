- **INV-CORE-login-blocking-transition-revokes-every-credential** Every transition that blocks
  a user's login (`SuspendUser`, `DeleteUser`, `DeprovisionSCIMUser`, `UpdateSCIMUser` with
  `active=false`, `UpdateUser` with `is_active=false`, `MigrateUserToMachine` with
  `suspendSource`, and `setAccountState` into every state `AccountLoginBlocked` refuses)
  deletes every session the user owns and every impersonation session the user started,
  revokes (not merely blocks) every PAT, removes the user's MFA step-up grants, tombstones
  every one of those session and PAT hashes in the auth cache, and writes exactly one audit
  row of its own event type. Why: #2855 (`DeprovisionSCIMUser`) and #3419 (`UpdateSCIMUser`
  deactivate) each skipped PAT revocation; a PAT is inert while the account is blocked, but
  `ReactivateUser` and `RestoreUser` revoke nothing, so an unrevoked row authenticates again
  after a restore. Guard: `internal/core/login_blocking_revoke_family_test.go`
  (`TestLoginBlockingTransitions_RevokeEveryCredential`, write-gated SQLite and Postgres;
  `TestLoginBlockingTransitions_Calibration` plants the #2855 shape, a state-only write and a
  missing audit row, each red) and, for completeness of that table,
  `internal/core/guards/login_blocking_transition_registry_guard_test.go`
  (`TestLoginBlockingTransitions_EveryLoginStateWriterIsClassified`: every core family function
  that writes `account_state` / `is_active` or soft-deletes a user is a table row or is
  classified with the reason it never blocks login). Not covered: the post-commit failure
  fallbacks (a failed listing or revoke), which have their own fault tests.
<!-- section: Account-state / exhaustiveness -->
