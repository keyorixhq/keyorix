- **INV-STORE-low-severity-row-writes-column-scoped** `rotation_policies`,
  `secret_templates` and `web_authn_credentials` have no full-row writer. A policy edit
  goes through `UpdateRotationPolicyFields` (the six operator-editable columns, scoped to
  `deleted_at IS NULL`), a template edit through `UpdateSecretTemplateFields`, and a
  credential through `DisableWebAuthnCredential` (`disabled` alone) or
  `SetWebAuthnCredentialCounterState` (the counter blob and `last_used_at`) — all four
  `RowsAffected`-checked, with the caller failing closed on no-match. Why: #2700 — the
  bare `Save`s these replace resurrected a soft-deleted rotation policy **active** (so it
  resumed driving rotation and breach alerts after a delete that reported success) and
  reverted the executor's `rotation_state`/`last_rotation_error`, hiding a failed
  rotation; and, on the two HARD-deleted models, re-INSERTED a concurrently deleted
  template or passkey via the same upsert fallback. The template and passkey cases are
  integrity/bookkeeping only (a re-inserted passkey returns with `disabled=true`, so it
  fails closed for authentication) and the severity is recorded as low rather than
  inflated. Note `RowsAffected` is the *entire* guarantee on the two models with no
  `deleted_at` — there is no soft-delete clause to lean on. Guard: `internal/core`
  `TestLowSeverityWrites_AreColumnScoped` (structural, all four bodies plus the three core
  entry points) and the four
  `TestCTAReview_{UpdateRotationPolicy_vs_DeleteRotationPolicy,UpdateRotationPolicy_vs_RotationStateFailed,UpdateSecretTemplate_vs_DeleteSecretTemplate,MarkWebAuthnCloned_vs_DeleteCredential}_CrossReplicaPostgres`
  (pg-gated, one per consequence).
