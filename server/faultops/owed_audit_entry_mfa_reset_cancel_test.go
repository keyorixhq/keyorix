package faultops

// MFA-RESET-TESTS-1 item 3: cancelling a pending MFA reset request narrows (it
// retires a request that could have cleared a second factor), so
// CancelMFAReset commits through withOwedAuditMutation: the request's cancellation is
// never blocked by the audit log, and its mfa.reset_cancelled row is written or queued
// exactly once. Found by this op's sweep: ClaimPendingAuditEvent / LogAuditEvent
// faults left the owed outcome and the unscoped oracle (a) reported it as a partial
// commit. Registered here, as its own file, instead of editing the two shared
// tables (owed_audit_oracle_test.go, owed_audit_oracle_expected_types_test.go).
func init() {
	const cancelOp = "REST POST /api/v1/mfa-reset-requests/{id}/cancel"
	owedAuditMoreOps = append(owedAuditMoreOps, cancelOp)
	owedAuditExpectedOwedTypes[cancelOp] = map[string]int{"mfa.reset_cancelled": 1}
}
