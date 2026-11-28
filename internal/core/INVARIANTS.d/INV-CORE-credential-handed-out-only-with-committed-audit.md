- **INV-CORE-credential-handed-out-only-with-committed-audit** A setup token
  (`IssueSetupToken`, and the invitation path `createInvitationWithSetupTokenAtomically`)
  is returned or delivered only when its `setup_token.issued` row was written in the mint's
  own transaction through a fail-closed target (`withAuditedMutation`); otherwise the
  supersede and insert roll back and the caller gets `ErrMutationAuditUnavailable`. A
  dynamic credential issued over a weak admin_dsn transport is minted only after its
  `dynamic_lease.insecure_transport` row was committed (the check runs before
  `engine.Issue`), like `dynamic_lease.issued` (#4716). Why: AUDIT-DISCLOSURE-NOV-1 items
  1-2: both writers discarded the audit result and handed the credential out anyway. Guard:
  `setup_token_issue_audit_fail_test.go`
  (`TestIssueSetupToken_AuditWriteFails_NoTokenAndPriorLinkStaysLive`,
  `TestInviteGlobalWithLink_SetupTokenAuditFails_NothingCreatedNothingDelivered`),
  `dynamic_secrets_insecure_transport_audit_fail_test.go`
  (`TestIssueLease_InsecureTransportAuditFails_NoCredentialNothingMinted`). Not covered:
  no static guard finds a new credential-issuing path that discards its audit result.
