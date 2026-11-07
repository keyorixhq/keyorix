package guards

// AUTHZ-GROUPROLE-TAILS-1 item 1: one exception for TestNoRoleReadErrorSkippedAsGone.
//
// ReconcileRBACPermissions is the startup top-up that grants a newly created permission to
// the canonical roles that should hold it. It decides nothing about an actor: a role it cannot
// read simply does not receive the new permission, so a fault narrows what the role can do
// (fails closed), it never lets a grant or a join through unchecked.
func init() {
	registerRoleReadSkipException("rbac_reconcile.go:ReconcileRBACPermissions",
		"startup permission top-up, no actor decision: a skipped role just does not receive the new permission (fails closed)")
}
