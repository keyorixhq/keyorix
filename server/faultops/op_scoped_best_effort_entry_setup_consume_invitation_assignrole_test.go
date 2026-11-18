// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

// The invitation_accept variant of POST /auth/setup/consume creates the account
// through c.CreateUser, whose baseline system_viewer grant is best-effort
// (besteffort.Run "users.CreateUser.AssignBaselineRole", internal/core/users.go):
// a fault in the AssignRole of system_viewer itself leaves the invitee with FEWER roles than the
// reference run and the accept succeeds. The same decision as
// op_scoped_best_effort_entry_post_users_assignrole_test.go for POST /api/v1/users/
// (PARTIAL-COMMIT-TAILS-NOV-3 item 2). The tables check keeps later AssignRole calls
// of this op, which are load-bearing grant steps with a wider diff, out of it.
func init() {
	registerOpScopedBestEffort("setup_consume_invitation_assignrole", opScopedBestEffortTable{
		op: setupInvitationOpKey, method: "AssignRole", tables: []string{"UserRole"}, minNthCall: 1,
		pinnedKinds: []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError},
	})
}
