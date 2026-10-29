package faultops

// NAMEDLOCK-OVERLAP-2 / REVFIX-3753-1: the standalone access-review revoke
// (RevokeAccessReviewGrant) now runs its removal in a transaction so the
// removal guard's fence runs first in it, and, as a revocation, commits through
// runOwedAuditMutation like RemoveUserRole: the removal is never blocked by the
// audit log, and its role.removed row is written or queued exactly once. The
// catalog scenario revokes a user's project role, so it owes that one row; the
// access_review.revoked decision row stays best-effort (logged after the
// commit). Found by TestOwedAuditOracle_EveryOwingCatalogOpIsScoped
// (ClaimPendingAuditEvent fired for an op outside the rule's scope).
// Registered here, as its own file, instead of editing the two shared tables
// (owed_audit_oracle_test.go, owed_audit_oracle_expected_types_test.go).
func init() {
	const revokeOp = "REST POST /api/v1/projects/{id}/access-review/revoke"
	owedAuditMoreOps = append(owedAuditMoreOps, revokeOp)
	owedAuditExpectedOwedTypes[revokeOp] = map[string]int{"role.removed": 1}
}
