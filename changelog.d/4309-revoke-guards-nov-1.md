### Testing
- **Family guards for credential revocation and delete sweeps.** One table test drives every
  transition that blocks login (`SuspendUser`, `DeleteUser`, `DeprovisionSCIMUser`,
  `UpdateSCIMUser` deactivate, `UpdateUser` deactivate, `MigrateUserToMachine` with suspend,
  and `setAccountState` into each blocked state) on SQLite and Postgres and asserts that
  sessions (including impersonation), PATs, step-up grants and auth-cache entries are all gone
  and one audit row is written; a static guard fails when a new account-state writer is not in
  that table. A second guard derives the tables with a `secret_id` column and fails when
  `DeleteSecret` and the project cascade do not sweep the same ones (#2797/#2798 class). The
  project child-write liveness guard now checks that the `LockLiveProject` re-check comes after
  the write and inside the same transaction. Test-only; no behaviour change.
