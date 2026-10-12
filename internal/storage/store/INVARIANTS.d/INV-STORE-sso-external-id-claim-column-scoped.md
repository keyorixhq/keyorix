- **INV-STORE-sso-external-id-claim-column-scoped** The SSO first-federation
  claim writes `external_id` through `ClaimUserExternalIDIfUnset` — `UPDATE users SET
  external_id, updated_at WHERE id = ? AND COALESCE(external_id,'') = '' AND deleted_at
  IS NULL` — never the full-row `UpdateUser`, and its caller re-reads the user
  afterwards so a login decision is made on the committed row, not on the snapshot read
  before the claim. Why: #2699 — `resolveSSOUser` persisted its unlocked `GetUserByEmail`
  snapshot with a GORM `Save`, so against an account deleted after that read the upsert
  fallback wrote `deleted_at=NULL, is_active=true, account_state=active` and `CompleteSSO`'s
  gate then passed the stale struct, minting a session for a deleted account; the same
  window reverted a concurrent suspension, password change, MFA enable or lockout.
  Guard: `internal/core` `TestResolveSSOUser_ClaimIsColumnScopedAndReReads` (structural,
  covers BOTH the write shape and the re-read) and
  `TestCTAReview_ResolveSSOUser_vs_DeleteUser_CrossReplicaPostgres` (pg-gated, asserts
  the row stays deleted AND that nothing login-capable is returned).
