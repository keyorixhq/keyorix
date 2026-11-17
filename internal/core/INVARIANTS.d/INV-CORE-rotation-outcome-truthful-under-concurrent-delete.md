- **INV-CORE-rotation-outcome-truthful-under-concurrent-delete** A write of a new secret
  version that loses a race with `DeleteSecret` reports what it stored. When the version
  commits together with its row update (`UpdateSecret` via `updateSecretWithNewVersion`,
  `RollbackSecret`, and a `RotateSecret` with no rotation backend), the row update matches no
  row of a deleted secret, the transaction rolls back, and the caller gets a plain
  `storage.ErrSecretNotFound`: nothing was stored. A backend-bound `RotateSecret` commits the
  version on its own, because the upstream credential may already be rotated and the version
  may be Keyorix's only record of it, so the version stays (and a restore serves it as
  latest). When its rotation stamp then finds the secret deleted, it returns
  `ErrRotatedValueStoredSecretDeleted` (it also matches `ErrSecretNotFound`, so the API still
  answers 404), naming the stored version, and `RunAutoRotation` audits "the new value was
  stored, but the secret was deleted during the rotation" instead of DRIFT. Do not "fix"
  this by putting both backend-bound writes in one transaction (see the comment at the write
  in `rotateSecret`). Do not refuse the version under a deleted parent with `lockLiveParent`
  either: on the backend-bound path that would throw away the record of a live credential.
  Why: #2873. The caller was told "secret not found" while a version had been stored, and
  the driver audited it as drift.
  Guard: `rotate_delete_interleaving_test.go`
  `TestRotateSecret_ConcurrentDelete_Interleavings_CrossReplicaPostgres` (pg-gated, two pools;
  all five rotate/rollback/update cases) and `_SQLite` (the two backend-bound cases, default
  CI), plus `TestRunAutoRotation_SecretDeletedDuringRotation_AuditsStoredNotDrift`. Each
  asserts the version rows, the returned error and the version a restore serves.
  **Not covered**: a stamp that fails for any reason other than "not found" after the
  version committed. That still reports "storing the new value failed" (DRIFT), although the
  value was stored (`TestRunAutoRotation_BackendSucceedsStoreFails_AuditsDrift` pins that
  wording).
