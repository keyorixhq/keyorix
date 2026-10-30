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
  transaction). Why: a reset that
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
  **UNGUARDED**: no static guard restricts the callers of `DeleteMFAForUser` /
  `DeleteWebAuthnCredential` to the reviewed paths (design §1 asks for one; follow-up), and
  the account-setup gate does not yet read `mfa_enrolment_required`.
