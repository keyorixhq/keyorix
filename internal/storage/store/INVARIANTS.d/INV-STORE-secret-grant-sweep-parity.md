- **INV-STORE-secret-grant-sweep-parity** `DeleteSecret` and `deleteProjectCascade` sweep the
  same set of per-secret grant tables (today `share_records`, `secret_acls` and approved
  `access_requests`), and every table with a `secret_id` column is swept by both or exempt
  with the reason it grants nothing (`access_review_items`, `secret_version_comments`). Why:
  #2798 (the cascade swept shares but not ACLs) and #2797 (neither closed approved
  secret-scoped access requests): a grant one path forgets comes back on `RestoreSecret` /
  `RestoreProject` with no re-authorization. Guard:
  `internal/core/guards/secret_grant_sweep_parity_guard_test.go`
  (`TestSecretGrantSweep_DeleteSecretAndProjectCascadeSweepTheSameTables`: the population is
  derived by gorm schema reflection over `internal/storage.AllModels()`, each path's sweep set
  from the models it and its callees reference; `TestSecretGrantSweep_Calibration`: a planted
  third table on one side, an unswept unexempted table and the #2798 regression are red).
  Whether each referenced table is swept for the right rows is proven per table by
  `local_lifecycle_cascade_test.go`. Not covered: a raw-SQL-only sweep with no `models.X`
  literal, and grant tables keyed by another column.
<!-- section: Soft-delete / purge races -->
