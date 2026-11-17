- **INV-CORE-expired-lease-revoked-under-deleted-parent** `RevokeExpiredLeases` revokes
  every expired `active` or `revoke_failed` lease, whatever the state of its parents: a
  config that `DeleteProject`'s #369 cascade (or an admin) disabled, and a soft-deleted
  project or environment, do not stop `RevokeLease` from dropping the credential on the
  target. Parent liveness gates minting (`IssueLease`, `RenewLease`, and
  `CreateDynamicSecretLease`'s write-then-check re-read of the enabled config, INV-STORE-21),
  never revocation. Do not add a liveness check to `RevokeLease` or the sweep: a lease that
  escaped the cascade's own revocation would then be a live credential nothing can drop.
  Why: #2652. The post-mint re-check closes the IssueLease vs DeleteProject window, and the
  sweep is what bounds any lease that still escapes it to its TTL.
  The race itself: `TestCTAReview_IssueLease_vs_DeleteProject_CrossReplicaPostgres` and
  `_DeleteProjectAfterInsert_` (pg-gated).
  The sweep also revokes after the project is purged: `PurgeDeletedProjectsBefore` does not
  remove `dynamic_secret_configs` (no `deleted_at`), and `GetDynamicSecretConfig` never reads
  the project (the `active_project_purged` case).
  Guard: `dynamic_secrets_sweep_deleted_project_test.go`
  `TestDynamicSecrets_SweepRevokesLeaseUnderDeletedProject` (default CI; active, revoke_failed,
  and purged project).
