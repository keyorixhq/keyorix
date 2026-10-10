- **INV-STORE-secret-row-writes-column-scoped** Every operation that edits a
  `secret_nodes` row writes only the columns it owns, through `UpdateSecretFields`
  (per-field pointers, `WHERE id = ? AND deleted_at IS NULL`, no-match reported so the
  caller fails closed), or — for the suspend/resume status CAS —
  `TransitionSecretStatus`, now whitelisted to `Status`/`UpdatedAt` instead of
  `Select("*")`. Columns no such caller owns are therefore unreachable from these
  paths: `deleted_at`, `read_count`, `status` (outside the CAS), the rotation columns,
  `project_id`/`environment_id`/`is_secret`, and the certificate cache. Why: #2695 —
  `UpdateSecret` was a bare `Save` of a struct read earlier and unlocked, and it was the
  SHARED primitive for eight operations, so each inherited both of its defects: the
  0-rows upsert fallback resurrected a concurrently deleted secret (shares and ACLs
  already revoked, no `secret.restored` audit, invisible to the restore UI and never
  reclaimed by the purge), and the full-row write reverted whatever a narrower
  concurrent writer had changed — `SuspendSecret`'s incident freeze,
  `TryIncrementSecretNodeReadCount`'s spent `MaxReads` budget,
  `ClearProjectSecretOwnership`'s offboarding. Note `UpdateSecretFields` normalises
  `expiration` to UTC itself, because a raw `Updates` bypasses `SecretNode.BeforeSave`
  (G81, see INV-STORE-19). Guard: `internal/core`
  `TestUpdateSecret_HasNoProductionCallerBeyond2668` (derived repo sweep, fails both on
  a new caller and on a stale allowance), `TestUpdateSecretWrites_AreColumnScoped`
  (structural, all eight call sites), `TestUpdateSecretRequest_FieldSetsMatch` (the two
  request-field readers cannot drift apart), and
  `TestCTAReview_{ClassifySecret_vs_DeleteSecret,BulkRenameSecrets_vs_SuspendSecret,SetSecretDescription_vs_ClearOwnership}_CrossReplicaPostgres`
  (pg-gated, one per consequence, each through a different caller).
