// One file per entry; never append to a shared list. See registry_entries_test.go.
// (This file registers the six rows of one call chain, so they stay together.)
package faultops

import "fmt"

func init() {
	// MFA-RESET-TESTS-1. CancelMFAReset's authorization is the actor's admin check
	// (isGlobalAdminRoleName, call #1 of each role read), which fails closed
	// (TestMFAReset_ActorAdminCheckFault_FailsClosed). Calls #2..#4 of
	// GetUserRoleIDsAt / GetUserGroupRoleIDsAt are globalAdminIDs' per-user admin
	// checks in notifyMFAResetAdmins, which runs after the cancellation committed to
	// pick who gets the notice.
	for _, method := range []string{"GetUserRoleIDsAt", "GetUserGroupRoleIDsAt"} {
		for nth := 2; nth <= 4; nth++ {
			registerNonLoadBearingAuthzRead(fmt.Sprintf("post_mfa_reset_cancel_%s_%d", method, nth), nonLoadBearingException{
				op: "REST POST /api/v1/mfa-reset-requests/{id}/cancel", method: method, nth: nth,
				designComment: "internal/core/mfa_reset.go CancelMFAReset: authorization is requireAdmin-style isGlobalAdminRoleName before " +
					"the transaction (denies on any error); the later role reads belong to notifyMFAResetAdmins -> globalAdminIDs, which " +
					"returns the error, is logged ('could not list the admins') and never fails the committed step",
				provingTest: "internal/core/TestMFAReset_RecipientFaultAfterCommit_IsBestEffort",
				why: "These calls pick notification recipients after the cancellation committed, not an authorization decision: the " +
					"actor was already authorized by a read that fails closed (TestMFAReset_ActorAdminCheckFault_FailsClosed). A fault here " +
					"loses the admin notice (logged), and failing the request would report an already-committed cancellation as failed.",
			})
		}
	}
}
