- **INV-STORE-machine-credential-classification-column-scoped** A machine-token
  credential's `classification` label is the only field any caller may change after
  issue, and it is written by `SetMachineIdentityCredentialClassification` — a
  conditional, column-scoped `UPDATE ... SET classification WHERE id = ? AND
  COALESCE(classification,'') = ?` that reports no-match rather than clobbering a
  concurrent classifier. `machine_identity_credentials` has NO full-row writer:
  `revoked` moves only through `RevokeMachineIdentityCredential` (an `UpdateColumn`)
  and `last_used_at` only through `TouchMachineIdentityCredential`. Why: #2696 — the
  former `UpdateMachineIdentityCredential` was a bare GORM `Save`, so
  `ClassifyMachineToken`'s unlocked read carried `revoked=false` back over a
  `RevokeMachineToken` that had committed on another replica and reported success,
  and the revoked token authenticated again with no audit record of the un-revoke.
  Guard: `internal/core` `TestClassifyMachineToken_IsColumnScoped` (structural, runs
  everywhere) and `TestCTAReview_ClassifyMachineToken_vs_RevokeMachineToken_CrossReplicaPostgres`
  (pg-gated, asserts the effect: the revoked token must not authenticate).
