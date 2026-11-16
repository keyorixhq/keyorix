### Fixed
- **`DeleteEnvironment` can no longer delete an environment a concurrent `RestoreProject` just revived (#4287).**
  On Postgres the storage call counted an environment's active secrets and soft-deleted the
  environment in separate statements, with nothing locking the environment row, so a restore
  could commit between the two and the environment was deleted with active secrets inside.
  It now row-locks the environment (unscoped `FOR UPDATE`) before the count, in the same
  transaction as the soft-delete. Not reachable through the API today (the scope middleware
  looks the environment up first). The `RestoreProject / SecretNode / Environment` row of
  `docs/child-parent-liveness-exempt.tsv` moves from `UNSAFE-OPEN` to `SERIALIZED`, proven by
  the two-pool Postgres test `TestDeleteEnvironment_CannotDeleteEnvironmentRevivedByConcurrentRestoreProject_Postgres`.
