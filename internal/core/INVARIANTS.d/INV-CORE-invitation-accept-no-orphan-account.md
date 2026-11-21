- **INV-CORE-invitation-accept-no-orphan-account** An invitation accept
  (`completeInvitationAccept`, a class-S saga) that fails after it created the account,
  by an error or a panic, leaves no live account: every step after `CreateUser` (the link
  spend, `applyInvitationGrants`, marking the invitation accepted) turns its panic into its
  error (`runInvitationAcceptStep`), and `abandonInvitationAccept` reverts the grants (the
  role grants and the membership journal row, moved to revoked, never left `active` with
  no role) and removes the account with its baseline `system_viewer` role and password history in one
  transaction (`removeInvitationAcceptAccount`); the invitation stays pending for a resend.
  An accept write that reports an error is read back first (`invitationAcceptLanded`): one
  that committed is kept and signed in, one that cannot be read back is undone (fail
  closed). An accept that committed and only failed to mint the session is kept and answered
  `ErrInvitationAcceptedSignInFailed` ("log in with your new password"). By design and not
  undone: the spent link (a consumed token never becomes live again), the dead-link
  answer's kept LoginAttempt slot, and a membership the grant had made, left revoked. A
  failed removal is audited MANUAL CLEANUP REQUIRED. Why: #4409 (a panic skipped the undo
  and left an account that could log in) and #4410 (the removed account kept its role and
  history). Guard: `internal/core/TestCompleteInvitationAccept_PanicAtEachStep_UndoesTheAccept`,
  `_FailureAtEachStep_UndoesAndSaysWhatHappened`, `_AcceptWriteLostAck_KeepsTheAccept`,
  `_AbandonRemovesBaselineRoleAndPasswordHistory`;
  `server/http/handlers/TestConsumeSetup_InvitationSignInFault_SaysLogInWithTheNewPassword`;
  `server/faultops` op `REST POST /auth/setup/consume#invitation_accept` (exhaustive with
  `TestOpFaultSweep`) with its consume-first entry (docs/atomicity-exempt.tsv
  `CONSUME:(*KeyorixCore).completeInvitationAccept`, class B) and its CreateSession
  oracle (a) by-design rows.
