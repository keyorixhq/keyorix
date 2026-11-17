- **INV-CORE-user-create-lost-ack-read-back** Every core function that inserts a user inside
  a transaction (`createUser`, `CreateUserWithAssignments`, `ProvisionSCIMUser`,
  `provisionSSOUser`, `bootstrapSystemLocked`, and any new one) reads a non-nil transaction error back with
  `userCreateLanded` before it answers: a create that committed and then reported an error (a
  lost acknowledgement) is answered as a success and continues down the success path
  (password-history seed, `auth.sso_jit_provisioned`, the SSO session, SCIM 201 with the id, the
  bootstrap's `user.created` / `project.created` and its token clear, under the bootstrap lock),
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
  A delivered create that ran through `withAuditedMutation` also forwards its committed audit
  rows off box (`flushDeliveredAudit` on the `errAuditCommitUnacknowledged` the transaction
  returned), exactly once; a rolled-back one forwards nothing
  (`TestWithAuditedMutation_LostAckDeliveredCreateForwardsItsAudit`).
  **Not covered**: a `withAuditedMutation` caller that does not read its mutation back answers
  the lost ack as an error and drops the forward (the audit row itself is committed).
