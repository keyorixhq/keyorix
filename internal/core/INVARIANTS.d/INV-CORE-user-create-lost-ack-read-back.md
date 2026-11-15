- **INV-CORE-user-create-lost-ack-read-back** Every core function that inserts a user inside
  a transaction (`createUser`, `CreateUserWithAssignments`, `ProvisionSCIMUser`,
  `provisionSSOUser`, and any new one) reads a non-nil transaction error back with
  `userCreateLanded` before it answers: a create that committed and then reported an error (a
  lost acknowledgement) is answered as a success and continues down the success path
  (password-history seed, `auth.sso_jit_provisioned`, the SSO session, SCIM 201 with the id),
  a create whose row is positively absent keeps its error, and a create whose read-back failed
  answers the error wrapped in `ErrUserCreateOutcomeUnknown` (SCIM: 503 + `Retry-After`). It
  never counts an unreadable outcome as landed. Why: #3225 / #4208 — a committed create
  answered 500, skipped its post-commit steps, and a retry met a duplicate; for SCIM the IdP
  never learned the new id, for SSO JIT the provisioning was never audited.
  Guard: `server/faultops` `TestPartialCommit_EveryUserCreateSiteHandlesLostAck` (derives the
  insert sites from the `storage.Storage` interface and the internal/core source; a site with
  no `userCreateLostAckSites` row, or a row whose function does not call `userCreateLanded`,
  fails; each in-scope row is driven commit-then-error and plain-error through its op), the
  per-path `TestPartialCommit_*` tests, and `TestUserCreateLanded_ReadBackOutcomes`.
  **Not covered**: `bootstrapSystemLocked` (row marked out of scope until #4218 merges); the
  off-box audit forward (`auditForwardSink.Flush`) of a `withAuditedMutation` create is skipped
  on a lost ack even when the row is delivered (the audit row itself is committed).
