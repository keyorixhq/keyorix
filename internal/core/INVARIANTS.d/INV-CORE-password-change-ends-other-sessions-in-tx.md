- **INV-CORE-password-change-ends-other-sessions-in-tx** `ChangePassword` deletes the
  account's other sessions (all but the caller's own, resolved before the change) in the
  same transaction as the new password hash (`applyNewPassword`). A failed purge rolls the
  change back: the caller is told it failed and the old password stays valid. Only the
  auth-cache eviction runs after the commit (best-effort, the delete is the control). The
  setup/reset-link consume does the same inside its own transaction
  (INV-CORE-setup-consume-all-or-nothing). Why: R1.16 (AUDIT-DISCLOSURE-NOV-1), same class
  as #4537: the purge ran after the commit and its failure was only logged, so a stolen
  session survived a change reported as successful. Guard:
  `password_change_session_revoke_fail_closed_test.go`
  (`TestChangePassword_SessionPurgeFails_ChangeRefusedOtherSessionCannotSurvive`). Not
  covered: the PAT revocation of `ChangePassword`, which stays post-commit and audited
  (`EventPasswordChangePATRevokeFailed`); MFA activate/disable, WebAuthn registration and
  SCIM deprovision still purge after their commit (`deleteSessionsForUserAndEvict`).
