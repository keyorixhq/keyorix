- **INV-CORE-mfa-reset-two-person-full-reset-audited** An administrator reset of another
  user's second factor (RECOVERY-MFA-RESET-1) is only ever a FULL credential reset, never
  "MFA off", and it has exactly one definition, `ResetMFACredentialsInTx`
  (`mfa_reset_effect.go`): TOTP secret, recovery codes, WebAuthn credentials and flag, and
  step-up grants removed; every session deleted and every PAT revoked; the password
  replaced by a one-time password with its expiry; the account `password_reset_required`
  and `mfa_enrolment_required`. Online it runs only from `ApproveMFAReset`, after a
  DIFFERENT human global admin than the requester (neither the target, both with a second
  factor proven afresh through `requireReauth`) approved a pending, unexpired request, in
  the same fail-closed transaction (`withAuditedMutation`) as the single-use request
  transition (`DecideMFAResetRequestIfPending`) and its `mfa.reset_approved` / `mfa.reset`
  rows. The host command (`server/admin/reset_mfa_logic.go`) applies the same function with
  its `admin.reset_mfa` row in its own transaction. Global admins, SSO/SCIM, suspended or
  inactive accounts and machine identities are refused on both paths. At approval the
  requester must still be an active, not login-blocked global admin, and the requester,
  approver (role, active, second factor) and target rules are re-checked on their row locks
  inside the approval transaction, locked in ascending user-ID order (#3800); at
  most one request per target is pending (decided on the target's row lock in the create
  transaction). Every dual-control refusal of an approval of an existing request (machine or
  non-admin approver, approver without a second factor, self- or target approval, request
  already decided or expired, requester no longer an active global admin, target refused
  by the target rules) leaves a DENIED `mfa.reset_approved` row, whether decided before the
  transaction or inside it (request decided meanwhile, requester, approver or target changed
  on the row lock): `auditMFAResetApprovalDenied` writes the in-transaction one through
  `c.storage` after the rollback, never on the transaction handle (MFA-RESET-TAILS-2; guards
  `mfa_reset_in_tx_denial_test.go` `TestMFAReset_InTxRefusal_*`,
  `mfa_reset_pre_tx_denial_test.go` `TestMFAReset_PreTxRefusal_LeavesDeniedRow`; the
  admin-rank-ceiling target refusal has no DENIED-row test of its own). Not
  covered by that row: an unknown request id, a storage error, and a failed
  re-authentication (`requireReauth` audits it as `mfa.failed` / `mfa.error`). An audit-log
  outage on approval answers HTTP 503 through `sendAuditUnavailable` (Retry-After, code
  `audit_unavailable`) and applies nothing (`server/http/handlers`
  `TestApproveMFAReset_AuditOutage_SharedAuditUnavailable503`). Why: a reset that
  keeps the password turns a stolen password into a takeover, and a one-admin reset is the
  single-admin takeover REISSUE-1 closed (docs/design/recovery-options.md §1). Guard:
  `mfa_reset_test.go` (`TestMFAReset_SelfApprovalRefusedAndAudited`,
  `TestMFAReset_SameAdminTwiceRefused`, `TestMFAReset_NonAdminOrMachineApproverRefused`,
  `TestMFAReset_TargetRulesRefused`, `TestMFAReset_ReplayOfApprovedRequestRefused`,
  `TestMFAReset_TwoAdmins_FullCredentialReset_EverySessionAndPATDead`,
  `TestMFAReset_AuditOutage_LeavesMFAIntact`), `mfa_reset_dual_control_test.go`
  (`TestMFAReset_RequesterNoLongerActive_ApprovalRefused`,
  `TestMFAReset_RequesterChangedInsideApproval_Refused`,
  `TestMFAReset_TargetChangedInsideApproval_Refused`,
  `TestMFAReset_ConcurrentRequestForSameTarget_OnlyOnePending`),
  `mfa_reset_approver_revocation_test.go` (`TestMFAReset_ApproverChangedInsideApproval_Refused`,
  `TestMFAReset_ApprovalLocksUsersInIDOrder`), `server/admin`
  `reset_mfa_test.go`.
  The callers that clear a second factor (`DeleteMFAForUser`, `DeleteWebAuthnCredential`,
  `SetUserMFAEnabled`/`SetUserWebAuthnEnabled` with anything but `true`, an assignment of
  `MFAEnabled`/`WebAuthnEnabled` to anything but `true`) are allowlisted by
  `internal/core/guards` `TestEverySecondFactorClearerCallerIsAllowlisted` (report-only
  until its first green nightly; calibration `TestSecondFactorClearerGuard_RejectsAnUnlistedCallSite`;
  what it does not see is in its header). The race guards are Postgres cross-replica tests
  that force the interleaving with barriers (#3801): `mfa_reset_cross_replica_test.go`
  `TestMFAReset_ConcurrentRequestsForSameTarget_CrossReplicaPostgres_RowLockDecides` (with
  its no-lock calibration) and `TestMFAReset_TwoAdminsApproveAtOnce_CrossReplica*_ExactlyOneWins`
  (the loser is refused inside its transaction).
  The account-setup gate reads `mfa_enrolment_required` (`MFAEnrolmentOwed`, an input of
  `PendingAccountSetupSteps` on HTTP and gRPC, #3799): a reset account owes enroll_mfa on
  every interactive session whether or not `security.require_mfa` is on, until a second
  factor is enrolled; TOTP activation and passkey registration (`FinishWebAuthnRegistration`)
  each clear the flag in the transaction that stores the factor, so removing that factor
  later does not owe the reset's enrolment again. Guard:
  `mfa_reset_enrolment_owed_test.go`, `mfa_reset_passkey_enrolment_test.go`
  (`TestMFAReset_PasskeyRegistrationClearsOwedEnrolment_SQLite`/`_Postgres`), `server/http`
  `TestAccountSetup_MFAResetOwesEnrolment_WithoutRequireMFA`, `server/grpc`
  `TestGRPCAccountSetup_MFAResetOwesEnrolment_WithoutRequireMFA`. Not seen: the login and
  profile responses' `pending_steps` (`PendingSetupStepsFor`, informational) do not report
  the owed step; the gate's 403 does.
